/* The workshop curriculum, as the dashboard understands it.
 *
 * This is the file to edit when the exercises change. `match` is a prefix on
 * the test class name: every test whose class starts with it belongs to that
 * exercise, and everything left over is treated as Foundations.
 *
 * A step may carry its own `match` as well, which is what ties a check to the
 * method you are actually writing. A step without one is shown as unchecked
 * rather than quietly counted as done -- the page must never imply that a step
 * is covered when no test looks at it.
 *
 * The step hints are the same ones the NotImplementedException messages carry,
 * so the page and the code say the same thing.
 *
 * This copy lives in the participant repository and is mounted over the one
 * baked into the coach image. The image ships the curriculum it was built with;
 * the repository ships the one its exercises actually are. */

window.MEDSIGN_EXERCISES = [
  {
    id: 1,
    title: 'Ask for a passkey',
    file: 'Lab/MedSignPasskeys.cs',
    match: 'MedSign.Tests.ExerciseOne',
    summary:
      'Registration begins with MedSign deciding what the browser should make: which relying ' +
      'party the key is bound to, which algorithm it has to speak, and a challenge nobody can ' +
      'predict. Fido2NetLib builds the ceremony; you decide what goes in it, and MedSign has ' +
      'to hold on to it -- the answer is worthless if there is nothing to check it against.',
    steps: [
      {
        method: 'BeginRegistration',
        match: 'MedSign.Tests.ExerciseOneBeginRegistration',
        hint: 'what the browser needs to answer for this account, and holding the ceremony it will be judged against.'
      }
    ]
  },
  {
    id: 2,
    title: 'Hand the ceremony to the browser',
    file: 'Endpoints/RegistrationEndpoints.cs',
    match: 'MedSign.Tests.ExerciseTwo',
    summary:
      'The ceremony has to reach navigator.credentials.create as JSON, which means every ' +
      'binary field arrives as base64url. This endpoint is also the first gate: a username ' +
      'that already has an account must not get a ceremony, or the sign-up form becomes a way ' +
      'to ask who works here.',
    steps: [
      {
        method: 'POST /registration-challenge',
        match: 'MedSign.Tests.ExerciseTwoRegistrationChallenge',
        hint: 'refuse an existing username, start the ceremony, and put it on the wire.'
      }
    ]
  },
  {
    id: 3,
    title: 'Verify what the authenticator made',
    file: 'Lab/MedSignPasskeys.cs',
    match: 'MedSign.Tests.ExerciseThree',
    summary:
      'The browser answers with an attestation object. Fido2NetLib checks the signature, the ' +
      'origin and the relying party for you -- against the ceremony you held, which is why ' +
      'holding it mattered. One question is left over that the library cannot answer on its ' +
      'own: whether this credential is already somebody else\'s.',
    steps: [
      {
        method: 'CompleteRegistrationAsync',
        match: 'MedSign.Tests.ExerciseThreeCompleteRegistration',
        hint: 'consume the held ceremony, have Fido2NetLib verify the response against it, and ask MedSignDb the one question the library cannot answer for itself.'
      }
    ]
  },
  {
    id: 4,
    title: 'Open the account',
    file: 'Endpoints/RegistrationEndpoints.cs',
    match: 'MedSign.Tests.ExerciseFour',
    summary:
      'What gets stored here is what every later sign-in is checked against: the credential ' +
      'id MedSign will be shown, the public key in the shape it can verify with, and the user ' +
      'handle the ceremony invented. A passkey another account already holds is a conflict, ' +
      'not a new account.',
    steps: [
      {
        method: 'POST /registration',
        match: 'MedSign.Tests.ExerciseFourRegistration',
        hint: 'complete the ceremony, refuse a credential that is already registered, persist the account, then issue a session.'
      }
    ]
  },
  {
    id: 5,
    title: 'Offer the keys that may answer',
    file: 'Lab/MedSignPasskeys.cs',
    match: 'MedSign.Tests.ExerciseFive',
    summary:
      'Sign-in starts with a challenge and a list of the credentials this account registered. ' +
      'The list is the interesting part: it is read by anyone who can post a username, so it ' +
      'must name this account\'s keys and nobody else\'s -- and a username with no account ' +
      'still has to get an answer.',
    steps: [
      {
        method: 'BeginSignInAsync',
        match: 'MedSign.Tests.ExerciseFiveBeginSignIn',
        hint: 'which credentials may answer, and holding the ceremony they will be judged against.'
      }
    ]
  },
  {
    id: 6,
    title: 'Give out the challenge',
    file: 'Endpoints/SignInEndpoints.cs',
    match: 'MedSign.Tests.ExerciseSix',
    summary:
      'The same JSON conversion as exercise 2, and the same discipline as exercise 5: an ' +
      'unknown username and a known one have to come back looking alike. A 404 here tells an ' +
      'attacker which accounts exist, one request at a time.',
    steps: [
      {
        method: 'POST /sign-in-challenge',
        match: 'MedSign.Tests.ExerciseSixSignInChallenge',
        hint: 'start a fresh ceremony, put it on the wire, and do not leak whether the account exists.'
      }
    ]
  },
  {
    id: 7,
    title: 'Check the signature',
    file: 'Lab/MedSignPasskeys.cs',
    match: 'MedSign.Tests.ExerciseSeven',
    summary:
      'The assertion is signed by the private half MedSign has never seen. Verifying it takes ' +
      'the held ceremony, the stored public key, and the counter -- which is how a cloned ' +
      'authenticator gets caught. The User Handle needs checking too: without it, a valid ' +
      'signature can be pointed at somebody else\'s account.',
    steps: [
      {
        method: 'CompleteSignInAsync',
        match: 'MedSign.Tests.ExerciseSevenCompleteSignIn',
        hint: 'the held ceremony, the stored key, the counter, and whether the User Handle belongs to this account.'
      }
    ]
  },
  {
    id: 8,
    title: 'Issue the session',
    file: 'Endpoints/SignInEndpoints.cs',
    match: 'MedSign.Tests.ExerciseEight',
    summary:
      'Last step, and the one that hands out a JWT. Two things have to hold: the new signature ' +
      'counter survives the request, or the clone check never fires again -- and every refusal ' +
      'looks the same from outside, whether the account is unknown, the credential is unknown, ' +
      'or the signature is simply wrong.',
    steps: [
      {
        method: 'POST /sign-in',
        match: 'MedSign.Tests.ExerciseEightSignIn',
        hint: 'verify the assertion, answer every refusal identically, persist the counter, and issue the session only after that.'
      }
    ]
  },
  {
    id: 9,
    title: 'Put the signing key behind the HSM boundary',
    file: 'Hsm/Device/HsmCommunicator.cs',
    match: 'MedSign.Tests.ExerciseNine',
    summary:
      'Implement the PKCS#11 boundary without ever handling private key material. Open one ' +
      'authenticated read/write session per operation, create a persistent non-extractable ' +
      'P-256 key pair, find each half by its label and class, expose only the public point, ' +
      'and ask the HSM to sign an already-computed digest. These checks use a simulated ' +
      'PKCS#11 device: incorrect code is stopped before it can operate on the workshop HSM.',
    steps: [
      {
        method: 'OpenSession',
        match: 'MedSign.Tests.ExerciseNineOpenSession',
        hint: 'resolve the configured PIN, select a slot with a token, open a read/write session, log in as CKU_USER, and clean up a session whose login fails.'
      },
      {
        method: 'CreateKey',
        match: 'MedSign.Tests.ExerciseNineCreateKey',
        hint: 'generate a persistent P-256 EC pair with matching labels; permit verification on the public half and signing on a sensitive, non-extractable private half, then return only the public point.'
      },
      {
        method: 'GetKey',
        match: 'MedSign.Tests.ExerciseNineGetKey',
        hint: 'find the public-key object by label, return null when it is absent, and otherwise return the validated public EC point.'
      },
      {
        method: 'SignDigest',
        match: 'MedSign.Tests.ExerciseNineSignDigest',
        hint: 'find the private-key object by label, fail safely when it is absent, and pass its handle and the unchanged digest to CKM_ECDSA.'
      },
      {
        method: 'FindOne',
        match: 'MedSign.Tests.ExerciseNineFindOne',
        hint: 'search by both CKA_LABEL and CKA_CLASS; return null for no match, the handle for exactly one, and refuse an ambiguous label before using either object.'
      },
      {
        method: 'ReadPoint',
        match: 'MedSign.Tests.ExerciseNineReadPoint',
        hint: 'read only CKA_EC_POINT, unwrap its optional DER OCTET STRING, and reject anything that is not an uncompressed 65-byte P-256 point.'
      }
    ]
  }
];
