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
        document.getElementById('forgot-panel').style.display = 'none';
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
    if (panel) {
        panel.querySelectorAll('.success-msg').forEach(s => s.style.display = 'none');
    }
}

function showSuccess(elementId, msg) {
    const el = document.getElementById(elementId);
    el.textContent = msg;
    el.style.display = 'block';
    const panel = el.closest('.form-panel');
    if (panel) {
        panel.querySelectorAll('.error-msg').forEach(s => s.style.display = 'none');
    }
}

// ==========================================
// TOGGLE PASSWORD
// ==========================================
document.querySelectorAll('.toggle-pwd').forEach(btn => {
    btn.addEventListener('click', function() {
        const targetId = this.dataset.target;
        const input = document.getElementById(targetId);
        if (input) {
            const isPassword = input.type === 'password';
            input.type = isPassword ? 'text' : 'password';
            this.textContent = isPassword ? 'Ẩn' : 'Hiện';
        }
    });
});

// ==========================================
// GOOGLE LOGIN
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
// EMAIL + PASSWORD LOGIN
// ĐÃ SỬA: dùng Cognito InitiateAuth API (USER_PASSWORD_AUTH)
// thay vì /oauth2/token (endpoint đó KHÔNG hỗ trợ grant_type=password,
// đó chính là nguyên nhân đăng nhập luôn thất bại dù mật khẩu đúng).
// ==========================================
document.getElementById('email-login-btn').addEventListener('click', async () => {
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    if (!email || !password) {
        showError('login-error', 'Vui lòng nhập email và mật khẩu');
        return;
    }

    try {
        const res = await fetch(cognitoApiEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AWSCognitoIdentityProviderService.InitiateAuth'
            },
            body: JSON.stringify({
                AuthFlow: 'USER_PASSWORD_AUTH',
                ClientId: appClientId,
                AuthParameters: {
                    USERNAME: email,   // email hoạt động vì đã cấu hình là alias
                    PASSWORD: password
                }
            })
        });

        const data = await res.json();

        const idToken = data?.AuthenticationResult?.IdToken;
        const accessToken = data?.AuthenticationResult?.AccessToken;
        const refreshToken = data?.AuthenticationResult?.RefreshToken;

        if (idToken) {
            chrome.storage.local.set({
                cognitoToken: idToken,
                cognitoAccessToken: accessToken,
                cognitoRefreshToken: refreshToken
            }, () => {
                showSuccess('login-success', 'Đăng nhập thành công! Đang chuyển hướng...');
                setTimeout(() => window.close(), 1500);
            });
        } else if (data?.ChallengeName) {
            // Trường hợp cần thêm bước xác thực (VD: NEW_PASSWORD_REQUIRED, MFA...)
            showError('login-error', 'Tài khoản yêu cầu bước xác thực bổ sung: ' + data.ChallengeName);
        } else {
            // Lỗi trả về từ Cognito API luôn nằm ở field __type + message
            const errType = data?.__type || '';
            let errorMsg = data?.message || 'Đăng nhập thất bại. Kiểm tra lại email/mật khẩu.';
            if (errType.includes('NotAuthorizedException')) {
                errorMsg = 'Sai email hoặc mật khẩu.';
            } else if (errType.includes('UserNotFoundException')) {
                errorMsg = 'Email chưa được đăng ký.';
            } else if (errType.includes('UserNotConfirmedException')) {
                errorMsg = 'Tài khoản chưa xác nhận email. Vui lòng kiểm tra hộp thư.';
            } else if (errType.includes('PasswordResetRequiredException')) {
                errorMsg = 'Tài khoản cần đặt lại mật khẩu.';
            }
            showError('login-error', errorMsg);
        }
    } catch (e) {
        console.error('[Login Error]', e);
        showError('login-error', 'Lỗi kết nối. Vui lòng thử lại.');
    }
});

// ==========================================
// REGISTER – SINH USERNAME NGẪU NHIÊN
// ==========================================
document.getElementById('register-btn').addEventListener('click', async () => {
    const email = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-password').value;
    if (!email || !password) {
        showError('reg-error', 'Vui lòng nhập email và mật khẩu');
        return;
    }
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
        showError('reg-error', 'Mật khẩu phải có ít nhất 8 ký tự, bao gồm chữ hoa, chữ thường, số và ký tự đặc biệt.');
        return;
    }

    const username = `user_${crypto.randomUUID()}`;

    try {
        const res = await fetch(cognitoApiEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AWSCognitoIdentityProviderService.SignUp'
            },
            body: JSON.stringify({
                ClientId: appClientId,
                Username: username,
                Password: password,
                UserAttributes: [{ Name: 'email', Value: email }]
            })
        });
        const data = await res.json();

        if (data.UserSub) {
            showSuccess('reg-success', 'Đăng ký thành công! Vui lòng kiểm tra email để lấy mã xác nhận.');
            document.getElementById('code-section').style.display = 'block';
            chrome.storage.local.set({ pendingConfirmEmail: email, pendingConfirmUsername: username });
        } else {
            const errType = data?.__type || '';
            let errorMsg = data.message || 'Đăng ký thất bại.';
            if (errType.includes('UsernameExistsException')) {
                errorMsg = 'Email đã được sử dụng.';
            } else if (errType.includes('InvalidPasswordException')) {
                errorMsg = 'Mật khẩu không đáp ứng yêu cầu.';
            }
            showError('reg-error', errorMsg);
        }
    } catch (e) {
        console.error('[Register Error]', e);
        showError('reg-error', 'Lỗi kết nối. Vui lòng thử lại.');
    }
});

// ==========================================
// CONFIRM – DÙNG USERNAME ĐÃ LƯU
// ==========================================
document.getElementById('confirm-btn').addEventListener('click', async () => {
    const code = document.getElementById('confirm-code').value.trim();
    if (!code) {
        showError('confirm-error', 'Vui lòng nhập mã xác nhận');
        return;
    }
    const { pendingConfirmUsername } = await chrome.storage.local.get('pendingConfirmUsername');
    if (!pendingConfirmUsername) {
        showError('confirm-error', 'Không tìm thấy thông tin đăng ký. Vui lòng đăng ký lại.');
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
                Username: pendingConfirmUsername,
                ConfirmationCode: code
            })
        });

        if (res.ok) {
            showSuccess('confirm-success', 'Xác nhận thành công! Bạn có thể đăng nhập ngay.');
            document.getElementById('code-section').style.display = 'none';
            chrome.storage.local.remove(['pendingConfirmEmail', 'pendingConfirmUsername']);
            document.querySelector('.tab-btn[data-tab="login"]').click();
        } else {
            const data = await res.json();
            showError('confirm-error', data.message || 'Mã xác nhận không đúng hoặc đã hết hạn.');
        }
    } catch (e) {
        console.error('[Confirm Error]', e);
        showError('confirm-error', 'Lỗi kết nối. Vui lòng thử lại.');
    }
});

// ==========================================
// QUÊN MẬT KHẨU
// ==========================================
document.getElementById('forgot-link').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('login-panel').classList.remove('active');
    document.getElementById('register-panel').classList.remove('active');
    document.getElementById('forgot-panel').style.display = 'block';
    document.getElementById('forgot-step-1').style.display = 'block';
    document.getElementById('forgot-step-2').style.display = 'none';
    ['forgot-error', 'forgot-success', 'forgot-reset-error', 'forgot-reset-success'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });
});

document.getElementById('forgot-back-btn').addEventListener('click', () => {
    document.getElementById('forgot-panel').style.display = 'none';
    document.getElementById('login-panel').classList.add('active');
});

document.getElementById('forgot-send-btn').addEventListener('click', async () => {
    const email = document.getElementById('forgot-email').value.trim();
    if (!email) {
        showError('forgot-error', 'Vui lòng nhập email');
        return;
    }

    try {
        const res = await fetch(cognitoApiEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AWSCognitoIdentityProviderService.ForgotPassword'
            },
            body: JSON.stringify({
                ClientId: appClientId,
                Username: email
            })
        });
        const data = await res.json();

        if (data.CodeDeliveryDetails) {
            showSuccess('forgot-success', 'Mã xác nhận đã được gửi đến email của bạn.');
            document.getElementById('forgot-step-1').style.display = 'none';
            document.getElementById('forgot-step-2').style.display = 'block';
            chrome.storage.local.set({ forgotEmail: email });
        } else {
            showError('forgot-error', data.message || 'Không thể gửi mã. Kiểm tra email.');
        }
    } catch (e) {
        console.error('[Forgot Error]', e);
        showError('forgot-error', 'Lỗi kết nối. Vui lòng thử lại.');
    }
});

document.getElementById('forgot-reset-btn').addEventListener('click', async () => {
    const code = document.getElementById('forgot-code').value.trim();
    const newPassword = document.getElementById('forgot-new-password').value;
    const confirmPassword = document.getElementById('forgot-confirm-password').value;

    if (!code || !newPassword || !confirmPassword) {
        showError('forgot-reset-error', 'Vui lòng nhập đầy đủ thông tin');
        return;
    }
    if (newPassword !== confirmPassword) {
        showError('forgot-reset-error', 'Mật khẩu xác nhận không khớp');
        return;
    }
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
        showError('forgot-reset-error', 'Mật khẩu phải có ít nhất 8 ký tự, bao gồm chữ hoa, chữ thường, số và ký tự đặc biệt.');
        return;
    }

    const { forgotEmail } = await chrome.storage.local.get('forgotEmail');
    if (!forgotEmail) {
        showError('forgot-reset-error', 'Không tìm thấy email. Vui lòng thử lại.');
        return;
    }

    try {
        const res = await fetch(cognitoApiEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AWSCognitoIdentityProviderService.ConfirmForgotPassword'
            },
            body: JSON.stringify({
                ClientId: appClientId,
                Username: forgotEmail,
                ConfirmationCode: code,
                Password: newPassword
            })
        });

        if (res.ok) {
            showSuccess('forgot-reset-success', 'Đặt lại mật khẩu thành công! Bạn có thể đăng nhập.');
            chrome.storage.local.remove('forgotEmail');
            setTimeout(() => {
                document.getElementById('forgot-panel').style.display = 'none';
                document.getElementById('login-panel').classList.add('active');
                document.getElementById('forgot-step-2').style.display = 'none';
                document.getElementById('forgot-step-1').style.display = 'block';
                document.getElementById('forgot-reset-success').style.display = 'none';
            }, 2000);
        } else {
            const data = await res.json();
            showError('forgot-reset-error', data.message || 'Mã xác nhận không đúng hoặc đã hết hạn.');
        }
    } catch (e) {
        console.error('[Reset Error]', e);
        showError('forgot-reset-error', 'Lỗi kết nối. Vui lòng thử lại.');
    }
});
