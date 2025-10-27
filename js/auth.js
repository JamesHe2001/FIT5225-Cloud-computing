// auth.js

async function login() {
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const message = document.getElementById("message");
  
    // Temporary hardcoded login
    if (email === "admin@monash.edu" && password === "admin123") {
      localStorage.setItem("jwt_token", "test-token");
      window.location.href = "mainActivity.html";
      return;
    }
  
    try {
      const response = await fetch("https://your-auth-api.com/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });
  
      if (!response.ok) {
        message.textContent = "Login failed. Check your credentials.";
        return;
      }
  
      const data = await response.json();
      localStorage.setItem("jwt_token", data.token);
      window.location.href = "mainActivity.html";
  
    } catch (err) {
      console.error("Login error:", err);
      message.textContent = "Error occurred during login.";
    }
  }
  
  async function register() {
    const firstname = document.getElementById("firstname").value;
    const lastname = document.getElementById("lastname").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const message = document.getElementById("message");
  
    try {
      const response = await fetch("https://your-auth-api.com/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ firstname, lastname, email, password })
      });
  
      if (!response.ok) {
        message.textContent = "Registration failed.";
        return;
      }
  
      message.style.color = "green";
      message.textContent = "Success! Redirecting...";
      setTimeout(() => {
        window.location.href = "login.html";
      }, 2000);
  
    } catch (err) {
      console.error("Register error:", err);
      message.textContent = "Error occurred during registration.";
    }
  }