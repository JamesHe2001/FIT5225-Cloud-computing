// search.js

requireAuth();
addBackToMainButton();

async function search() {
  const tag = document.getElementById("tag1").value;
  const count = document.getElementById("count1").value;
  const resultsDiv = document.getElementById("results");
  resultsDiv.innerHTML = "";

  if (!tag || !count) {
    alert("Please enter both tag and count.");
    return;
  }

  const query = {};
  query[tag] = parseInt(count);

  try {
    const response = await fetch("https://your-api.com/search", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + localStorage.getItem("jwt_token")
      },
      body: JSON.stringify(query)
    });

    const data = await response.json();

    data.links.forEach(link => {
      const fileId = link.split('/').pop().replace("-thumb.jpg", ".jpg");
      const a = document.createElement("a");
      a.href = `result.html?file_id=${fileId}`;

      const img = document.createElement("img");
      img.src = link;
      img.alt = fileId;

      a.appendChild(img);
      resultsDiv.appendChild(a);
    });

  } catch (err) {
    console.error("Search error:", err);
    resultsDiv.textContent = "Search failed.";
  }
}