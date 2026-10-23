
const promptInput = document.getElementById("prompt");
const analyzeButton = document.getElementById("analyze-btn");
const clearButton = document.getElementById("clear-btn");
const charCount = document.getElementById("char-count");
const results = document.getElementById("results");

const patterns = [
  {
    name: "Instruction override",
    regex: /\b(ignore|disregard|forget|override|bypass)\b.{0,70}\b(previous|prior|all|above|earlier|system|instructions?|rules?)\b/i,
    points: 40
  },
  {
    name: "Secret or sensitive information request",
    regex: /\b(reveal|expose|disclose|leak|print|show)\b.{0,60}\b(secret|password|admin code|credentials?|api key|hidden prompt|system prompt)\b/i,
    points: 35
  },
  {
    name: "Roleplay or unrestricted persona",
    regex: /\b(pretend|roleplay|act as|you are now)\b.{0,100}\b(hacker|unrestricted|no rules|no restrictions|boss|developer mode)\b/i,
    points: 25
  },
  {
    name: "Suspicious output instruction",
    regex: /\b(say|write|output|respond with|print)\b.{0,60}\b(PWNED|secret|password|admin code)\b/i,
    points: 20
  },
  {
    name: "Instruction hierarchy manipulation",
    regex: /\b(system prompt|developer message|hidden instructions)\b.{0,70}\b(ignore|override|replace|reveal|change)\b/i,
    points: 30
  },
  {
    name: "Possible obfuscated instruction",
    regex: /\b(1gn0re|d1sregard|pr3tend|1nstructi0ns)\b/i,
    points: 25
  }
];

function analyzeText(text) {
  const findings = [];

  for (const pattern of patterns) {
    if (pattern.regex.test(text)) {
      findings.push({
        name: pattern.name,
        points: pattern.points
      });
    }
  }

  // Detect some attempts to hide instructions with Unicode format characters.
  if (/\p{Cf}/u.test(text)) {
    findings.push({
      name: "Hidden Unicode format characters",
      points: 30
    });
  }

  // This browser demo intentionally uses transparent, simple rules.
  // It does not decode arbitrary payloads or understand all context.
  const score = Math.min(
    100,
    findings.reduce((total, item) => total + item.points, 0)
  );

  let level = "Low";
  if (score >= 60) {
    level = "High";
  } else if (score >= 25) {
    level = "Medium";
  }

  return { findings, score, level };
}

function showResults(text) {
  if (!text.trim()) {
    alert("Please enter some text to analyze.");
    promptInput.focus();
    return;
  }

  const report = analyzeText(text);

  document.getElementById("result-title").textContent =
    report.score >= 25
      ? "Potential warning signs detected"
      : "No strong warning signs detected";

  document.getElementById("result-summary").textContent =
    report.score >= 25
      ? "Review this text before using it with an AI system."
      : "The rules did not identify strong warning signs. This does not prove the text is safe.";

  document.getElementById("risk-score").textContent =
    `${report.score}/100`;

  document.getElementById("risk-level").textContent = report.level;

  document.getElementById("finding-count").textContent =
    report.findings.length;

  const findingsList = document.getElementById("findings-list");
  findingsList.replaceChildren();

  if (report.findings.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No matching rules were triggered.";
    findingsList.appendChild(item);
  } else {
    for (const finding of report.findings) {
      const item = document.createElement("li");
      item.textContent =
        `${finding.name} (+${finding.points} points)`;
      findingsList.appendChild(item);
    }
  }

  const recommendation = document.getElementById("recommendation");

  if (report.level === "High") {
    recommendation.textContent =
      "Recommendation: Hold for human review. Do not automatically trust or execute this input.";
  } else if (report.level === "Medium") {
    recommendation.textContent =
      "Recommendation: Review the flagged text and its context before using it.";
  } else {
    recommendation.textContent =
      "Recommendation: No strong rule matched. Continue to apply normal safety checks.";
  }

  results.hidden = false;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

promptInput.addEventListener("input", () => {
  charCount.textContent = `${promptInput.value.length} characters`;
});

analyzeButton.addEventListener("click", () => {
  showResults(promptInput.value);
});

clearButton.addEventListener("click", () => {
  promptInput.value = "";
  charCount.textContent = "0 characters";
  results.hidden = true;
  promptInput.focus();
});

promptInput.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    showResults(promptInput.value);
  }
});
