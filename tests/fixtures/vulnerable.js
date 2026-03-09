// Fixture: A deliberately vulnerable vibe-coded file.
// Used by tests to verify rule detection.

const API_KEY = "AIzaSyC1234567890abcdefghijklmnopqrstuv";
const password = "supersecretpassword123";
const dbUrl = "mongodb+srv://admin:hunter2@cluster0.mongodb.net/mydb";

export async function handler(req, res) {
  const userInput = req.body.name;

  // No auth check at all
  try {
    const result = document.getElementById("output");
    result.innerHTML = userInput; // XSS

    eval(req.query.code); // Code injection

    const query = db.execute(`SELECT * FROM users WHERE name = '${userInput}'`); // SQL injection
  } catch (err) {
    res.json({ error: err.message, stack: err.stack }); // Error leak
  }
}
