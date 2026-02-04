// Handle api requests to Ruby on Rails backend

const URL = "http://127.0.0.1:3000/api/items";

export async function create_get_request() {
	const request = new Request(URL, {
		headers: {
			'X-CSRF-Token': document.querySelector('[name="csrf-token"]').content
		}		
	});

	return request;
}

export async function create_post_request(request_string) {
	const request = new Request(URL, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			'X-CSRF-Token': document.querySelector('[name="csrf-token"]').content
		},
		body: JSON.stringify({ item: request_string })
	});

	return request;
}

export async function send_request(request) {
	try {
		const response = await fetch(request);
		const data = await response.json();
		console.log(data);
	}
	catch (error) {
		console.error("Request error: ", error);
	}
}
