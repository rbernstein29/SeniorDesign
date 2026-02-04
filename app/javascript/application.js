// Entry point for the build script in your package.json
import { create_get_request, create_post_request, send_request } from "./api/api.js";

// Handle user login and account creation

// Buttons for toggle between sign in and create account
const signin_toggle_btn = document.getElementById("tab-signin");
const create_account_toggle_btn = document.getElementById("tab-signup");
const signin_toggle_tab = document.getElementById("view-signin");
const create_account_toggle_tab = document.getElementById("view-signup");

// Show sign in page
async function toggle_signin() {
	create_account_toggle_btn.className = "tab";
	create_account_toggle_tab.className = "body hidden";
	signin_toggle_btn.className = "tab active";
	signin_toggle_tab.className = "body";
}

// Show sign up page
async function toggle_create_account() {
	signin_toggle_btn.className = "tab";
	signin_toggle_tab.className = "body hidden";
	create_account_toggle_btn.className = "tab active";
	create_account_toggle_tab.className = "body";
}

// Toggles
signin_toggle_btn.addEventListener("click", toggle_signin);
create_account_toggle_btn.addEventListener("click", toggle_create_account);


// Handle sign in of user
async function signin() {
	const email = document.getElementById("in-email").value;
	const pass = document.getElementById("in-pass").value;
	const remember_me = document.getElementById("in-remember").checked;

	console.log("Email: ", email, " Password: ", pass, "Remember Me: ", remember_me);

	const user = { name: email, description: pass };

	const request = await create_post_request(user);
	const response = await send_request(request);

	console.log(response);
}

// Sign in button and event
const signin_btn = document.getElementById("btn-signin");
signin_btn.addEventListener("click", signin);


// Handle account creation
async function create_account() {
	const name = document.getElementById("up-name").value;
	const org = document.getElementById("up-org").value;
	const email = document.getElementById("up-email").value;
	const pass = document.getElementById("up-pass").value;
	const terms = document.getElementById("up-terms").checked;

	console.log("Name: ", name, "Org: ", org, "Email: ", email, "Password: ", pass, "Terms : ", terms)
}

// Create account button and event
const create_account_btn = document.getElementById("btn-signup");
create_account_btn.addEventListener("click", create_account);
