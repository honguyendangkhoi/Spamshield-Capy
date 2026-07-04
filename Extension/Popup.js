document.addEventListener('DOMContentLoaded', () => {
    // ... tất cả các biến cũ giữ nguyên ...

    // ==========================================
    // USER INFO & LOGOUT
    // ==========================================
    const userAvatar = document.getElementById('user-avatar');
    const userEmailDisplay = document.getElementById('user-email-display');
    const btnLogout = document.getElementById('btn-logout');
    const btnLoginInline = document.getElementById('btn-login-inline');

    function updateUserUI() {
        chrome.storage.local.get(['cognitoToken'], (data) => {
            if (data.cognitoToken) {
                try {
                    const payload = JSON.parse(atob(data.cognitoToken.split('.')[1]));
                    const email = payload.email || 'Người dùng';
                    userEmailDisplay.textContent = email;
                    userAvatar.textContent = email.charAt(0).toUpperCase();
                    btnLogout.style.display = 'block';
                    btnLoginInline.style.display = 'none';
                } catch (e) {
                    showNotLoggedInUI();
                }
            } else {
                showNotLoggedInUI();
            }
        });
    }

    function showNotLoggedInUI() {
        userEmailDisplay.textContent = 'Chưa đăng nhập';
        userAvatar.textContent = '?';
        btnLogout.style.display = 'none';
        btnLoginInline.style.display = 'block';
    }

    btnLogout.addEventListener('click', () => {
        if (confirm('Bạn có chắc muốn đăng xuất?')) {
            chrome.runtime.sendMessage({ action: 'LOGOUT' }, () => {
                updateUserUI();
                // Có thể reset giao diện nếu cần
                showIdle();
            });
        }
    });

    btnLoginInline.addEventListener('click', () => {
        chrome.tabs.create({ url: chrome.runtime.getURL('login.html') });
    });

    updateUserUI();
    // ... phần còn lại giữ nguyên ...
});
