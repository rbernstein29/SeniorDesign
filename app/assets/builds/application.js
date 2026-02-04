// app/javascript/api/api.js
var URL = "http://127.0.0.1:3000/api/items";
async function create_post_request(request_string) {
  const request = new Request(URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": document.querySelector('[name="csrf-token"]').content
    },
    body: JSON.stringify({ item: request_string })
  });
  return request;
}
async function send_request(request) {
  try {
    const response = await fetch(request);
    const data = await response.json();
    console.log(data);
  } catch (error) {
    console.error("Request error: ", error);
  }
}

// app/javascript/application.js
var signin_toggle_btn = document.getElementById("tab-signin");
var create_account_toggle_btn = document.getElementById("tab-signup");
var signin_toggle_tab = document.getElementById("view-signin");
var create_account_toggle_tab = document.getElementById("view-signup");
async function toggle_signin() {
  create_account_toggle_btn.className = "tab";
  create_account_toggle_tab.className = "body hidden";
  signin_toggle_btn.className = "tab active";
  signin_toggle_tab.className = "body";
}
async function toggle_create_account() {
  signin_toggle_btn.className = "tab";
  signin_toggle_tab.className = "body hidden";
  create_account_toggle_btn.className = "tab active";
  create_account_toggle_tab.className = "body";
}
signin_toggle_btn.addEventListener("click", toggle_signin);
create_account_toggle_btn.addEventListener("click", toggle_create_account);
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
var signin_btn = document.getElementById("btn-signin");
signin_btn.addEventListener("click", signin);
async function create_account() {
  const name = document.getElementById("up-name").value;
  const org = document.getElementById("up-org").value;
  const email = document.getElementById("up-email").value;
  const pass = document.getElementById("up-pass").value;
  const terms = document.getElementById("up-terms").checked;
  console.log("Name: ", name, "Org: ", org, "Email: ", email, "Password: ", pass, "Terms : ", terms);
}
var create_account_btn = document.getElementById("btn-signup");
create_account_btn.addEventListener("click", create_account);
//# sourceMappingURL=/assets/application.js.map
