const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

const message = document.getElementById('message');
const registerButton = document.getElementById('register-button');
const loginButton = document.getElementById('login-button');
const usernameInput = document.getElementById('username');
const loginUsernameInput = document.getElementById('login-username');

registerButton.addEventListener('click', async () => {
    const username = usernameInput.value;
    if (!username) {
        message.textContent = 'Please enter a username';
        return;
    }

    try {
        const resp = await fetch('/register/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username }),
        });

        const options = await resp.json();
        if (options.error) {
            throw new Error(options.error);
        }

        const attestation = await startRegistration(options);

        const verificationResp = await fetch('/register/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(attestation),
        });

        const verificationJSON = await verificationResp.json();
        if (verificationJSON.error) {
            throw new Error(verificationJSON.error);
        }

        message.textContent = `Successfully registered ${verificationJSON.username}!`;
    } catch (error) {
        message.textContent = `Error: ${error.message}`;
    }
});

loginButton.addEventListener('click', async () => {
    const username = loginUsernameInput.value;
    if (!username) {
        message.textContent = 'Please enter a username';
        return;
    }

    try {
        const location = await new Promise((resolve, reject) => {
            if (!navigator.geolocation) {
                reject(new Error('Geolocation is not supported by your browser'));
            } else {
                navigator.geolocation.getCurrentPosition(
                    (position) => resolve({
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                    }),
                    () => reject(new Error('Unable to retrieve your location')),
                );
            }
        });

        const resp = await fetch('/login/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username }),
        });

        const options = await resp.json();
        if (options.error) {
            throw new Error(options.error);
        }

        const assertion = await startAuthentication(options);

        const verificationResp = await fetch('/login/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ credential: assertion, location }),
        });

        const verificationJSON = await verificationResp.json();
        if (verificationJSON.error) {
            throw new Error(verificationJSON.error);
        }

        message.textContent = `Successfully clocked in ${verificationJSON.username}!`;
    } catch (error) {
        message.textContent = `Error: ${error.message}`;
    }
});
