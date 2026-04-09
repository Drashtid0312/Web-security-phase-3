const welcomeMessage = document.getElementById("welcomeMessage");
const currentName = document.getElementById("currentName");
const currentEmail = document.getElementById("currentEmail");
const currentBio = document.getElementById("currentBio");

const profileForm = document.getElementById("profileForm");
const nameInput = document.getElementById("name");
const emailInput = document.getElementById("email");
const bioInput = document.getElementById("bio");

const nameError = document.getElementById("nameError");
const emailError = document.getElementById("emailError");
const bioError = document.getElementById("bioError");

const messageBox = document.getElementById("messageBox");
const logoutBtn = document.getElementById("logoutBtn");
const yearEl = document.getElementById("year");

if (yearEl) {
  yearEl.textContent = new Date().getFullYear();
}

function showMessage(message, type) {
  messageBox.textContent = message;
  messageBox.classList.remove("hidden", "success", "error");
  messageBox.classList.add(type);
}

function clearMessage() {
  messageBox.textContent = "";
  messageBox.classList.add("hidden");
  messageBox.classList.remove("success", "error");
}

function clearErrors() {
  nameError.textContent = "";
  emailError.textContent = "";
  bioError.textContent = "";
}

function validateForm(name, email, bio) {
  let isValid = true;
  clearErrors();

  const namePattern = /^[A-Za-z\s]{3,50}$/;
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const bioPattern = /^[A-Za-z0-9\s.,!?'"-]{0,500}$/;

  if (!namePattern.test(name)) {
    nameError.textContent = "Name must be 3 to 50 alphabetic characters.";
    isValid = false;
  }

  if (!emailPattern.test(email)) {
    emailError.textContent = "Please enter a valid email address.";
    isValid = false;
  }

  if (!bioPattern.test(bio)) {
    bioError.textContent = "Bio must be under 500 characters with no HTML tags or unsafe special characters.";
    isValid = false;
  }

  return isValid;
}

async function loadProfile() {
  try {
    const response = await fetch("/api/profile", {
      method: "GET",
      credentials: "include"
    });

    const data = await response.json();

    if (!response.ok) {
      showMessage(data.message || "Failed to load profile.", "error");
      return;
    }

    const user = data.user;

    welcomeMessage.textContent = `Welcome back, ${user.name || "User"}`;
    currentName.textContent = user.name || "";
    currentEmail.textContent = user.email || "";
    currentBio.textContent = user.bio || "";

    nameInput.value = user.name || "";
    emailInput.value = user.email || "";
    bioInput.value = user.bio || "";
  } catch (error) {
    showMessage("An error occurred while loading your profile.", "error");
  }
}

profileForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMessage();

  const name = nameInput.value.trim();
  const email = emailInput.value.trim();
  const bio = bioInput.value.trim();

  if (!validateForm(name, email, bio)) {
    return;
  }

  try {
    const response = await fetch("/api/profile/update", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      credentials: "include",
      body: JSON.stringify({ name, email, bio })
    });

    const data = await response.json();

    if (!response.ok) {
      if (data.errors) {
        if (data.errors.name) nameError.textContent = data.errors.name;
        if (data.errors.email) emailError.textContent = data.errors.email;
        if (data.errors.bio) bioError.textContent = data.errors.bio;
      }

      showMessage(data.message || "Profile update failed.", "error");
      return;
    }

    currentName.textContent = data.user.name || "";
    currentEmail.textContent = data.user.email || "";
    currentBio.textContent = data.user.bio || "";
    welcomeMessage.textContent = `Welcome back, ${data.user.name || "User"}`;

    showMessage(data.message || "Profile updated successfully.", "success");
  } catch (error) {
    showMessage("An error occurred while updating your profile.", "error");
  }
});

logoutBtn.addEventListener("click", async () => {
  try {
    const response = await fetch("/logout", {
      method: "POST",
      credentials: "include"
    });

    window.location.href = "/login";
  } catch (error) {
    window.location.href = "/login";
  }
});

loadProfile();