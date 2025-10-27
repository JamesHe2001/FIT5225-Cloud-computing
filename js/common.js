// common.js

// Check if user is authenticated
function requireAuth() {
    const token = localStorage.getItem("jwt_token");
    if (!token) {
      window.location.href = "login.html";
    }
  }
  
  // Add a "Back to Main Menu" button
  function addBackToMainButton() {
    const back = document.createElement("a");
    back.href = "mainActivity.html";
    back.className = "back-btn";
    back.textContent = "← Back to Main Menu";
    document.body.insertBefore(back, document.body.firstChild);
  }
  
  // Logout function
  function logout() {
    localStorage.removeItem("jwt_token");
    window.location.href = "login.html";
  }