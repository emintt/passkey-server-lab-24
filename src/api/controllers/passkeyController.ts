import { NextFunction, Request, Response } from 'express';
import CustomError from '../../classes/CustomError';
import { User } from '@sharedTypes/DBTypes';
import { UserResponse } from '@sharedTypes/MessageTypes'

import { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from '@simplewebauthn/types';
import fetchData from '../../utils/fetchData';
import { generateAuthenticationOptions, GenerateAuthenticationOptionsOpts, generateRegistrationOptions, verifyAuthenticationResponse, VerifyAuthenticationResponseOpts, verifyRegistrationResponse, VerifyRegistrationResponseOpts } from '@simplewebauthn/server';
import { Challenge, PasskeyUserGet } from '../../types/PasskeyTypes';
import challengeModel from '../models/challengeModel';
import passkeyUserModel from '../models/passkeyUserModel';
import authenticatorDeviceModel from '../models/authenticatorDeviceModel';

// check environment variables
if (
  !process.env.NODE_ENV ||
  !process.env.RP_ID ||
  !process.env.AUTH_URL ||
  !process.env.JWT_SECRET ||
  !process.env.RP_NAME
) {
  throw new Error('Environment variables not set');
}

const {
  NODE_ENV,
  RP_ID,
  AUTH_URL,
  // JWT_SECRET,
  RP_NAME} = process.env;


// Registration handler
const setupPasskey = async (
  req: Request<{}, {}, User>,
  res: Response<{ email: string, options:  PublicKeyCredentialCreationOptionsJSON}>,
  next: NextFunction
) => {
  try {
    // Register user with AUTH API
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req.body),
    };
    const userResponse = await fetchData<UserResponse>(
      process.env.AUTH_URL + '/api/v1/users',
      options,
    );

    if (!userResponse) {
      next(new CustomError('User not created', 400));
      return;
    }
    // Generate registration options
    const regOptions = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: userResponse.user.username,
      attestationType: 'none',
      timeout: 60000,
      authenticatorSelection: {
        residentKey: 'discouraged',
        userVerification: 'preferred'
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    // Save challenge to DB,
    // challenge giong nhu token, lien quan den  regoptions,
    // tren dt phai co challenge token
    const challenge: Challenge = {
      email: userResponse.user.email,
      challenge: regOptions.challenge,
    };

    await new challengeModel(challenge).save();

    // Add user to PasskeyUser collection
    await new passkeyUserModel({
      email: userResponse.user.email,
      userId: userResponse.user.user_id,
      devices: [],
    }).save();

    // Send response with email and options
    res.json({
      email: userResponse.user.email,
      options: regOptions,
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Registration verification handler
const verifyPasskey = async (
  req: Request<{}, {}, {email: string, registrationOptions: RegistrationResponseJSON}>,
  res: Response<UserResponse>,
  next: NextFunction
) => {
  try {
    // TODO: Retrieve expected challenge from DB
    const expectedChallenge = await challengeModel.findOne({
      email: req.body.email,
    });

    if (!expectedChallenge) {
      next(new CustomError('Challenge not found', 404));
      return;
    }

    // Verify registration response
    const opts: VerifyRegistrationResponseOpts = {
      response: req.body.registrationOptions,
      expectedChallenge: expectedChallenge.challenge,
      expectedOrigin: NODE_ENV === 'development'
        ? `http://${RP_ID}:5173`
        : `https://${RP_ID}` , // expectedOrigin: client origin
      expectedRPID: RP_ID
    };
    console.log('opts', opts);

    // tää vastaa bcrypt verify, testaa response täsmä niin kuin optsin arvot. chllenge saadaan tietokannasta
    const verification = await verifyRegistrationResponse(opts);
    console.log('verification', verification);

    const { verified, registrationInfo } = verification;

    if (!verified || !registrationInfo) {
      next(new CustomError('Verification failed', 403));
      return;
    };

    const { credentialID, counter, credentialPublicKey } = registrationInfo;    // TODO: Check if device is already registered
    const existingDevice = await authenticatorDeviceModel.findOne({
      credentialID,
    });

    if (existingDevice) {
      next(new CustomError('Device already registered', 400));
      return;
    }
    // Save new authenticator to AuthenticatorDevice collection
    const newDevice = new authenticatorDeviceModel({
      email: req.body.email,
      credentialPublicKey: Buffer.from(credentialPublicKey),
      credentialID,
      counter,
      transports: req.body.registrationOptions.response.transports,
    });

    const newDeviceResult = await newDevice.save();


    // Update user devices array in DB
    const user =  await passkeyUserModel.findOne({email: req.body.email});
    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }
    user.devices.push(newDeviceResult._id);
    await user.save();

    // Clear challenge from DB after successful registration
    await challengeModel.findOneAndDelete({email: req.body.email});

    // Retrieve and send user details from AUTH API
    // If valid, get the user from AUTH API
    const response = await fetchData<UserResponse>(
      AUTH_URL + '/api/v1/users/' + user.userId,
    );

    res.json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Generate authentication options handler
const authenticationOptions = async (
  req: Request<{}, {}, {email: string}>,
  res: Response<PublicKeyCredentialRequestOptionsJSON>,
  next: NextFunction
) => {
  try {
    // Retrieve user and associated devices from DB
    const user = await passkeyUserModel
      .findOne({
        email: req.body.email,
      })
      .populate('devices') as unknown as PasskeyUserGet;
    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }
    // Generate authentication options
    const opts: GenerateAuthenticationOptionsOpts = {
      timeout: 60000,
      rpID: RP_ID,
      allowCredentials: user.devices.map((device) => ({
        id: device.credentialID,
        type: 'public-key',
        transports: device.transports,
      })),
      userVerification: 'preferred',
    };

    const authOptions = await generateAuthenticationOptions(opts);

    // Save challenge to DB
    await new challengeModel({
      email: req.body.email,
      challenge: authOptions.challenge,
    }).save();

    // Send options in response
    res.send(authOptions);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Authentication verification and login handler
const verifyAuthentication = async (
  req: Request<{}, {}, {email: string, authResponse: AuthenticationResponseJSON}>,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, authResponse } = req.body;
    const expectedChallenge = await challengeModel.findOne({
      email: email
    });

    if (!expectedChallenge) {
      next(new CustomError('Challenge not found', 404));
      return;
    }

    // Retrieve expected challenge from DB
    const user = (await passkeyUserModel
      .findOne({email})
      .populate('devices')) as unknown as PasskeyUserGet;

    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }

    // Verify authentication response
    const opts: VerifyAuthenticationResponseOpts = {
      response: authResponse,
      expectedChallenge: expectedChallenge.challenge,
      expectedOrigin:
        NODE_ENV === 'development'
          ? `http://${RP_ID}:5173`
          : `https://${RP_ID}`,
      authenticator: {
        credentialPublicKey: Buffer.from(user.devices[0].credentialPublicKey),
        credentialID: user.devices[0].credentialID,
        counter: user.devices[0].counter,
      },
      requireUserVerification: false,
      expectedRPID: RP_ID, // TODO: fix this
    };

    const verification = await verifyAuthenticationResponse(opts);

    const { verified, authenticationInfo } = verification;

    // Update authenticator's counter to prevent replay attack
    if (!verified) {
      // user.devices[0].counter = authenticationInfo.newCounter; //newCouner on sisärakennettu
      await authenticatorDeviceModel.findByIdAndUpdate(
        user.devices[0]._id,
        // user.devices[0], // sama kuin ala oleva rivi
        { counter: authenticationInfo.newCounter },
      );
    }
    // Clear challenge from DB after successful authentication
    await challengeModel.findByIdAndDelete({email});
    // TODO: Generate and send JWT token
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {
  setupPasskey,
  verifyPasskey,
  authenticationOptions,
  verifyAuthentication,
};
