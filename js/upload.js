// upload.js

requireAuth();
addBackToMainButton();

async function uploadFile() {
  const fileInput = document.getElementById("mediaFile");
  const status = document.getElementById("status");

  const file = fileInput.files[0];
  if (!file) {
    alert("Please select a file.");
    return;
  }

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch("https://your-api.com/upload", {
      method: "POST",
      body: formData,
      headers: {
        Authorization: "Bearer " + localStorage.getItem("jwt_token")
      }
    });

    if (!response.ok) {
      status.textContent = "Upload failed.";
      return;
    }

    status.textContent = "Upload successful!";
  } catch (error) {
    console.error("Upload error:", error);
    status.textContent = "Error occurred during upload.";
  }
}