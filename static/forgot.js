// DOM Elements
const findAccountBtn = document.getElementById('findAccountBtn');
const verifyAnswerBtn = document.getElementById('verifyAnswerBtn');
const resetPasswordBtn = document.getElementById('resetPasswordBtn');
const backToStep1 = document.getElementById('backToStep1');
const backToStep2 = document.getElementById('backToStep2');

const identifierInput = document.getElementById('identifier');
const securityAnswerInput = document.getElementById('securityAnswer');
const newPasswordInput = document.getElementById('newPassword');
const confirmPasswordInput = document.getElementById('confirmPassword');

let currentUser = null;

// Step navigation
function showStep(stepNumber) {
    // Hide all steps
    document.querySelectorAll('.form-step').forEach(step => {
        step.classList.remove('active');
    });
    
    // Update step indicators
    document.querySelectorAll('.step').forEach((step, index) => {
        step.classList.remove('active', 'completed');
        if (index + 1 < stepNumber) {
            step.classList.add('completed');
        } else if (index + 1 === stepNumber) {
            step.classList.add('active');
        }
    });
    
    // Show current step
    document.getElementById(`stepForm${stepNumber}`).classList.add('active');
}

// Alert functions
function showAlert(message, type = 'error') {
    const alertContainer = document.getElementById('alertContainer');
    alertContainer.innerHTML = `
        <div class="alert alert-${type}">
            ${message}
        </div>
    `;
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        alertContainer.innerHTML = '';
    }, 5000);
}

// Step 1: Find Account
findAccountBtn.addEventListener('click', async () => {
    const identifier = identifierInput.value.trim();
    
    if (!identifier) {
        showAlert('Please enter your username or email');
        return;
    }
    
    findAccountBtn.disabled = true;
    findAccountBtn.textContent = 'Searching...';
    
    try {
        const response = await fetch('/find-account', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ identifier })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentUser = data.user;
            document.getElementById('securityQuestion').innerHTML = `
                <p><strong>Security Question:</strong></p>
                <p>${data.security_question}</p>
            `;
            showStep(2);
            showAlert('Account found! Please answer your security question.', 'success');
        } else {
            showAlert(data.error || 'Account not found');
        }
    } catch (error) {
        showAlert('Network error. Please try again.');
    } finally {
        findAccountBtn.disabled = false;
        findAccountBtn.textContent = 'Find Account';
    }
});

// Step 2: Verify Security Answer
verifyAnswerBtn.addEventListener('click', async () => {
    const answer = securityAnswerInput.value.trim();
    
    if (!answer) {
        showAlert('Please enter your security answer');
        return;
    }
    
    verifyAnswerBtn.disabled = true;
    verifyAnswerBtn.textContent = 'Verifying...';
    
    try {
        const response = await fetch('/verify-security-answer', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                user_id: currentUser._id,
                answer: answer 
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showStep(3);
            showAlert('Security answer verified! Now set your new password.', 'success');
        } else {
            showAlert(data.error || 'Incorrect security answer');
            securityAnswerInput.value = '';
        }
    } catch (error) {
        showAlert('Network error. Please try again.');
    } finally {
        verifyAnswerBtn.disabled = false;
        verifyAnswerBtn.textContent = 'Verify Answer';
    }
});

// Step 3: Reset Password
resetPasswordBtn.addEventListener('click', async () => {
    const newPassword = newPasswordInput.value.trim();
    const confirmPassword = confirmPasswordInput.value.trim();
    
    if (!newPassword || !confirmPassword) {
        showAlert('Please fill in both password fields');
        return;
    }
    
    if (newPassword.length < 8) {
        showAlert('Password must be at least 8 characters long');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showAlert('Passwords do not match');
        return;
    }
    
    resetPasswordBtn.disabled = true;
    resetPasswordBtn.textContent = 'Resetting...';
    
    try {
        const response = await fetch('/reset-password-final', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                user_id: currentUser._id,
                new_password: newPassword 
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showAlert('Password reset successfully! Redirecting to login...', 'success');
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } else {
            showAlert(data.error || 'Failed to reset password');
        }
    } catch (error) {
        showAlert('Network error. Please try again.');
    } finally {
        resetPasswordBtn.disabled = false;
        resetPasswordBtn.textContent = 'Reset Password';
    }
});

// Back button handlers
backToStep1.addEventListener('click', () => {
    showStep(1);
    securityAnswerInput.value = '';
});

backToStep2.addEventListener('click', () => {
    showStep(2);
    newPasswordInput.value = '';
    confirmPasswordInput.value = '';
});

// Password strength indicator
newPasswordInput.addEventListener('input', () => {
    const password = newPasswordInput.value;
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    
    const strengthText = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'][strength];
    const strengthColor = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#16a34a'][strength];
    
    // You can add a strength indicator element if needed
});

// Confirm password validation
confirmPasswordInput.addEventListener('input', () => {
    const newPassword = newPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    
    if (confirmPassword && newPassword !== confirmPassword) {
        confirmPasswordInput.style.borderColor = '#ef4444';
    } else {
        confirmPasswordInput.style.borderColor = '#d1d5db';
    }
});
