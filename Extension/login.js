// ==========================================
// Tab switching
// ==========================================
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const target = btn.dataset.tab;
        document.getElementById('login-panel').classList.toggle('active', target === 'login');
        document.getElementById('register-panel').classList.toggle('active', target === 'register');
    });
});

// ==========================================
// COGNITO CONFIG (từ env.js)
// ==========================================
const cognitoDomain = `https://${COGNITO_CONFIG.domain}`;
const appClientId = COGNITO_CONFIG.appClientId;
const redirectUri = chrome.identity.getRedirectURL('oauth2callback');
const cognitoApiEndpoint = `https://cognito-idp.${COGNITO_CONFIG.region}.amazonaws.com`;

// ==========================================
// HELPER FUNCTIONS
// ==========================================
function showError(elementId, msg) {
    const el = document.getElementById(elementId);
    el.textContent = msg;
    el.style.display = 'block';
    const panel = el.closest('.form-panel');
    panel.querySelectorAll('.success-msg').forEach(s => s.style.display = 'none');
}

function showSuccess(elementId, msg) {
    const el = document.getElementById(elementId);
    el.textContent = msg;
    el.style.display = 'block';
    const panel = el.closest('.form-panel');
    panel.querySelectorAll('.error-msg').forEach(s => s.style.display = 'none');
}

// ==========================================
// GOOGLE LOGIN (giữ prompt=select_account)
// ==========================================
document.getElementById('google-login').addEventListener('click', () => {
    const authUrl = `${cognitoDomain}/oauth2/authorize?identity_provider=Google&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=token&client_id=${appClientId}&scope=openid+email&prompt=select_account`;
    chrome.identity.launchWebAuthFlow({ url: authUrl, interactive: true }, (redirectUrl) => {
        if (chrome.runtime.lastError) {
            showError('login-error', 'Đăng nhập Google thất bại: ' + chrome.runtime.lastError.message);
            return;
        }
        try {
            const params = new URLSearchParams(new URL(redirectUrl).hash.substring(1));
            const idToken = params.get('id_token');
            if (idToken) {
                chrome.storage.local.set({ cognitoToken: idToken }, () => {
                    showSuccess('login-success', 'Đăng nhập Google thành công! Đang chuyển hướng...');
                    setTimeout(() => window.close(), 1500);
                });
            } else {
                const error = params.get('error');
                showError('login-error', 'Lỗi từ Google: ' + (error || 'Không lấy được token'));
            }
        } catch (e) {
            showError('login-error', 'Lỗi xử lý đăng nhập Google');
        }
    });
});

// ==========================================
// MICROSOFT LOGIN (bỏ prompt để tránh lỗi)
// ==========================================
document.getElementById('microsoft-login').addEventListener('click', () => {
    const authUrl = `${cognitoDomain}/oauth2/authorize?identity_provider=Microsoft&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=token&client_id=${appClientId}&scope=openid+email`;
    chrome.identity.launchWebAuthFlow({ url: authUrl, interactive: true }, (redirectUrl) => {
        if (chrome.runtime.lastError) {
            showError('login-error', 'Đăng nhập Microsoft thất bại: ' + chrome.runtime.lastError.message);
            return;
        }
        try {
            const params = new URLSearchParams(new URL(redirectUrl).hash.substring(1));
            const idToken = params.get('id_token');
            if (idToken) {
                chrome.storage.local.set({ cognitoToken: idToken }, () => {
                    showSuccess('login-success', 'Đăng nhập Microsoft thành công! Đang chuyển hướng...');
                    setTimeout(() => window.close(), 1500);
                });
            } else {
                const error = params.get('error');
                showError('login-error', 'Lỗi từ Microsoft: ' + (error || 'Không lấy được token'));
            }
        } catch (e) {
            showError('login-error', 'Lỗi xử lý đăng nhập Microsoft');
        }
    });
});

// ==========================================
// EMAIL + PASSWORD LOGIN
// ==========================================
document.getElementById('email-login-btn').addEventListener('click', async () => {
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    if (!email || !password) {
        showError('login-error', 'Vui lòng nhập email và mật khẩu');
        return;
    }
    try {
        const res = await fetch(`${cognitoDomain}/oauth2/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'password',
                client_id: appClientId,
                username: email,
                password: password
            })
        });
        const data = await res.json();
        if (data.id_token) {
            chrome.storage.local.set({ cognitoToken: data.id_token }, () => {
                showSuccess('login-success', 'Đăng nhập thành công! Đang chuyển hướng...');
                setTimeout(() => window.close(), 1500);
            });
        } else {
            showError('login-error', data.message || 'Đăng nhập thất bại. Kiểm tra lại email/mật khẩu.');
        }
    } catch (e) {
        showError('login-error', 'Lỗi kết nối. Vui lòng thử lại.');
    }
});

// ==========================================
// REGISTER (SIGN UP)
// ==========================================
document.getElementById('register-btn').addEventListener('click', async () => {
    const email = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-password').value;
    if (!email || !password) {
        showError('reg-error', 'Vui lòng nhập email và mật khẩu');
        return;
    }
    try {
        const res = await fetch(cognitoApiEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AWSCognitoIdentityProviderService.SignUp'
            },
            body: JSON.stringify({
                ClientId: appClientId,
                Username: email,
                Password: password,
                UserAttributes: [{ Name: 'email', Value: email }]
            })
        });
        const data = await res.json();
        if (data.UserSub) {
            showSuccess('reg-success', 'Đăng ký thành công! Vui lòng kiểm tra email để lấy mã xác nhận.');
            document.getElementById('code-section').style.display = 'block';
            chrome.storage.local.set({ pendingConfirmEmail: email });
        } else {
            showError('reg-error', data.message || 'Đăng ký thất bại.');
        }
    } catch (e) {
        showError('reg-error', 'Lỗi kết nối. Vui lòng thử lại.');
    }
});

// ==========================================
// CONFIRM SIGN UP
// ==========================================
document.getElementById('confirm-btn').addEventListener('click', async () => {
    const code = document.getElementById('confirm-code').value.trim();
    if (!code) {
        showError('confirm-error', 'Vui lòng nhập mã xác nhận');
        return;
    }
    const { pendingConfirmEmail } = await chrome.storage.local.get('pendingConfirmEmail');
    if (!pendingConfirmEmail) {
        showError('confirm-error', 'Không tìm thấy email cần xác nhận. Vui lòng đăng ký lại.');
        return;
    }
    try {
        const res = await fetch(cognitoApiEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AWSCognitoIdentityProviderService.ConfirmSignUp'
            },
            body: JSON.stringify({
                ClientId: appClientId,
                Username: pendingConfirmEmail,
                ConfirmationCode: code
            })
        });
        if (res.ok) {
            showSuccess('confirm-success', 'Xác nhận thành công! Bạn có thể đăng nhập ngay.');
            document.getElementById('code-section').style.display = 'none';
            chrome.storage.local.remove('pendingConfirmEmail');
            document.querySelector('.tab-btn[data-tab="login"]').click();
        } else {
            const data = await res.json();
            showError('confirm-error', data.message || 'Mã xác nhận không đúng.');
        }
    } catch (e) {
        showError('confirm-error', 'Lỗi kết nối. Vui lòng thử lại.');
    }
});
