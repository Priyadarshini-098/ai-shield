
const promptInput = document.getElementById("prompt");
const analyzeButton = document.getElementById("analyze-btn");
const clearButton = document.getElementById("clear-btn");
const charCount = document.getElementById("char-count");
const results = document.getElementById("results");

const MAX_INPUT_LENGTH = 12000;

// Normalize common obfuscation without changing the text shown to the user.
function normalizeText(text) {
  return text
    .normalize("NFKC")
    .replace(/\p{Cf}/gu, "")
    .replace(/[іӏ]/gi, "i")
    .replace(/[оօ]/gi, "o")
    .replace(/[ее]/gi, "e")
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function hasAny(text, patterns) {
  return patterns.some(pattern => pattern.test(text));
}

function analyzeText(originalText) {
  const text = normalizeText(originalText);
  const findings = [];
  let score = 0;

  function addFinding(name, points, explanation) {
    findings.push({ name, points, explanation });
    score += points;
  }

  const override = hasAny(text, [
    /\b(ignore|disregard|forget|override|bypass|abandon)\b.{0,100}\b(previous|prior|earlier|above|all|system|developer|safety|rules|instructions)\b/,
    /\b(start over|new instructions|instructions no longer apply)\b/,
    /\b(do not follow|stop following)\b.{0,70}\b(rules|instructions|policy|safety)\b/
  ]);

  const roleplay = hasAny(text, [
    /\b(pretend|roleplay|role play|imagine|act as|play the role|simulate)\b/,
    /\b(you are now|become|from now on you are)\b/
  ]);

  const unrestrictedPersona = hasAny(text, [
    /\b(no rules|without restrictions|unrestricted|uncensored|jailbreak)\b/,
    /\b(ignore safety|bypass safety|remove your limitations)\b/,
    /\b(hacker ai|evil ai|developer mode)\b/
  ]);

  const sensitiveTarget = hasAny(text, [
    /\b(secret|password|passcode|admin code|access code|credentials|api key|private key)\b/,
    /\b(hidden prompt|system prompt|developer instructions|confidential data)\b/,
    /\b(database login|security token|private information)\b/
  ]);

  const disclosureAction = hasAny(text, [
    /\b(reveal|expose|disclose|leak|extract|retrieve|obtain|steal|print|output|tell|show|give|share|uncover)\b/,
    /\b(find out|get access to|hand over|send me|write down|repeat back)\b/
  ]);

  const authorityImpersonation = hasAny(text, [
    /\b(you are the boss|act as the administrator|pretend to be the owner)\b/,
    /\b(i am your (admin|administrator|developer|creator|boss))\b/,
    /\b(as the (admin|administrator|owner|developer|boss))\b/
  ]);

  const instructionAssembly = hasAny(text, [
    /\b(join|combine|concatenate|assemble|merge|put together)\b.{0,100}\b(words|parts|pieces|strings|fragments|result)\b/,
    /\b(remember|store|keep in mind)\b.{0,100}\b(join|combine|assemble|repeat|output)\b/,
    /\b(first part|second part|next fragment|separate pieces)\b/
  ]);

  const suspiciousOutput = hasAny(text, [
    /\b(say|write|output|respond with|print|repeat)\b.{0,60}\b(pwned|secret|password|admin code)\b/,
    /\b(return only|output only|respond only)\b/
  ]);

  const encodedOrHidden = hasAny(text, [
    /\b(base64|decode this|encoded payload|hidden message|invisible instruction)\b/,
    /\b(zero width|unicode escape|hex encoded)\b/
  ]) || /\p{Cf}/u.test(originalText);

  // Look for relationships between intent, target, and context.
  // A roleplay request by itself is not automatically an attack.
  if (override) {
    addFinding(
      "Instruction override attempt",
      30,
      "The text appears to replace, ignore, or bypass earlier instructions."
    );
  }

  if (roleplay && unrestrictedPersona) {
    addFinding(
      "Unrestricted roleplay",
      30,
      "The roleplay context is combined with a request for an unrestricted or rule-free persona."
    );
  }

  if (roleplay && sensitiveTarget && disclosureAction) {
    addFinding(
      "Roleplay-based sensitive information request",
      35,
      "The scenario asks for sensitive information through a role or fictional situation."
    );
  } else if (sensitiveTarget && disclosureAction) {
    addFinding(
      "Sensitive information disclosure",
      35,
      "The text combines a sensitive target with an action that may disclose or retrieve it."
    );
  }

  if (authorityImpersonation && (sensitiveTarget || disclosureAction)) {
    addFinding(
      "Possible authority impersonation",
      25,
      "The prompt invokes an authority role alongside a potentially sensitive request."
    );
  }

  if (instructionAssembly && (suspiciousOutput || sensitiveTarget || override)) {
    addFinding(
      "Possible split-instruction attack",
      25,
      "The text may be combining separate steps to build a final instruction or output."
    );
  }

  if (encodedOrHidden) {
    addFinding(
      "Possible hidden or encoded content",
      20,
      "The text mentions concealed content, encoding, or contains Unicode format characters."
    );
  }

  if (suspiciousOutput && !findings.some(
    finding => finding.name === "Sensitive information disclosure"
      || finding.name === "Roleplay-based sensitive information request"
  )) {
    addFinding(
      "Constrained or suspicious output request",
      10,
      "The prompt demands a specific output. This is only a weak signal on its own."
    );
  }

  // Avoid double-counting every related rule at full strength.
  score = Math.min(100, score);

  let level = "Low";
  if (score >= 60) {
    level = "High";
  } else if (score >= 25) {
    level = "Medium";
  }

  return { findings, score, level };
}

function showResults(originalText) {
  if (!originalText.trim()) {
    alert("Please enter some text to analyze.");
    promptInput.focus();
    return;
  }

  if (originalText.length > MAX_INPUT_LENGTH) {
    alert(`Please keep your input under ${MAX_INPUT_LENGTH} characters.`);
    return;
  }

  const report = analyzeText(originalText);

  document.getElementById("result-title").textContent =
    report.level === "High"
      ? "High-risk warning signs detected"
      : report.level === "Medium"
        ? "Potential warning signs detected"
        : "No strong warning signs detected";

  document.getElementById("result-summary").textContent =
    report.level === "High"
      ? "Several risk signals were found. Hold this prompt for human review."
      : report.level === "Medium"
        ? "Some risk signals were found. Review the context before using this prompt."
        : "Few or no warning signals matched. This does not prove the prompt is safe.";

  document.getElementById("risk-score").textContent =
    `${report.score}/100`;
  document.getElementById("risk-level").textContent = report.level;
  document.getElementById("finding-count").textContent =
    report.findings.length;

  const findingsList = document.getElementById("findings-list");
  findingsList.replaceChildren();

  if (report.findings.length === 0) {
    const item = document.createElement("li");
    item.textContent =
      "No matching risk patterns were identified by this rule-based demo.";
    findingsList.appendChild(item);
  } else {
    for (const finding of report.findings) {
      const item = document.createElement("li");
      const title = document.createElement("strong");
      const detail = document.createElement("p");

      title.textContent = `${finding.name} (+${finding.points} points)`;
      detail.textContent = finding.explanation;

      item.append(title, detail);
      findingsList.appendChild(item);
    }
  }

  document.getElementById("recommendation").textContent =
    report.level === "High"
      ? "Recommended action: hold for human review. Do not automatically execute or trust the input."
      : report.level === "Medium"
        ? "Recommended action: inspect the flagged behavior and relevant context."
        : "Recommended action: continue applying normal safety controls. A low score is not a safety guarantee.";

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

promptInput.addEventListener("keydown", event => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    showResults(promptInput.value);
  }
});



