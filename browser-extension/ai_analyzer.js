/**
 * TRON THE DLP AGENT — AI-Powered File Analyzer
 * Uses Google Gemini API to analyze file content for sensitive data
 * that regex patterns cannot catch (context, intent, business data).
 *
 * Runs in the service worker alongside the regex scanner.
 */

const GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models";
const GEMINI_MODEL = "gemini-2.0-flash";

/**
 * Mask sensitive values before anything is sent to the LLM.
 * Uses the raw values from the regex findings plus a fresh local regex pass
 * (scanner.js), replacing each with a typed placeholder such as [REDACTED:SSN].
 */
function redactForLLM(text, regexFindings) {
    let out = String(text || "");
    const values = new Map();
    const collect = (findings) => {
        for (const f of findings || []) {
            const v = String(f?.matched_text || "");
            if (v.length >= 4 && !values.has(v)) values.set(v, String(f?.pattern_name || "SENSITIVE"));
        }
    };
    collect(regexFindings);
    if (typeof scanText === "function") {
        try { collect(scanText(out, "llm-redaction")); } catch (_) { /* best effort */ }
    }
    // Longest first so overlapping matches are fully masked.
    const ordered = [...values.entries()].sort((a, b) => b[0].length - a[0].length);
    for (const [value, name] of ordered) {
        out = out.split(value).join(`[REDACTED:${name}]`);
    }
    return out;
}

/**
 * Analyze file content with Gemini AI.
 * Returns AI analysis with risk assessment, categories, and recommendations.
 */
async function analyzeWithAI(fileContent, fileName, domain, regexFindings, apiKey, isImage = false) {
    if (!apiKey) {
        return { enabled: false, error: "No API key configured" };
    }

    // Truncate content for text to avoid token limits (first 15,000 chars)
    let contentSample = fileContent;
    if (!isImage && fileContent.length > 15000) {
        contentSample = fileContent.substring(0, 15000) + "\n\n[... content truncated ...]";
    }
    // Raw sensitive values never leave the browser: mask them in the text sent to Gemini.
    if (!isImage) {
        contentSample = redactForLLM(contentSample, regexFindings);
    }

    // Build context from regex findings (values redacted, only the finding type is shared)
    const regexSummary = regexFindings.length > 0
        ? regexFindings.slice(0, 10).map(f => `- ${f.description}: [REDACTED:${f.pattern_name || "SENSITIVE"}]`).join("\n")
        : "No regex pattern matches found.";

    const prompt = `You are a DLP (Data Loss Prevention) security analyst for a browser extension. A user is about to upload a file to a website. Analyze the file content and determine if it contains sensitive, confidential, or dangerous data that should NOT be uploaded.

FILE INFORMATION:
- File Name: ${fileName}
- Upload Target: ${domain}
- File Size: ${contentSample.length} characters

REGEX SCANNER FINDINGS:
${regexSummary}

FILE CONTENT:
\`\`\`
${contentSample}
\`\`\`

Analyze this content and respond with ONLY this JSON (no markdown, no extra text):
{
  "risk_level": "critical|high|medium|low|none",
  "risk_score": 0-100,
  "should_block": true/false,
  "categories": ["list of detected sensitive data categories"],
  "findings": [
    {
      "type": "finding type (e.g., PII, Financial, Credentials, Proprietary Code, Confidential Business Data, Medical Records, Legal Documents)",
      "description": "what was found",
      "severity": "critical|high|medium|low",
      "evidence": "brief quote or reference (redacted if needed)"
    }
  ],
  "context_analysis": "Brief analysis of the upload context — is this file appropriate to upload to this domain?",
  "recommendation": "BLOCK|WARN|ALLOW",
  "reasoning": "Brief explanation of your decision"
}

IMPORTANT RULES:
1. Be thorough — look for PII, financial data, credentials, API keys, passwords, proprietary source code, trade secrets, confidential business data, medical records, legal privileged info, customer databases, internal communications.
2. Consider the upload CONTEXT — uploading a resume to LinkedIn is fine, uploading a customer database to pastebin is NOT.
3. Look for patterns that regex CAN'T catch: confidential project names, internal server names, employee lists, salary data, meeting notes with sensitive topics, NDA-covered content.
4. Err on the side of caution for critical/high findings.
7. Return ONLY valid JSON, no markdown code fences.`;

    let requestBody = {};

    if (isImage) {
        // Strip out the data URL prefix (e.g., data:image/png;base64,)
        const contentString = String(fileContent || '');
        const base64Data = contentString.split(',')[1] || contentString;

        // Prefer MIME from data URL, then infer from extension.
        // This avoids passing WEBP/TIFF bytes as JPEG, which causes model parse failures.
        let mimeType = 'image/jpeg';
        const dataUrlMatch = contentString.match(/^data:([^;]+);base64,/i);
        if (dataUrlMatch && dataUrlMatch[1]) {
            mimeType = dataUrlMatch[1].toLowerCase();
        } else {
            const name = String(fileName || '').toLowerCase();
            if (name.endsWith('.png')) mimeType = 'image/png';
            else if (name.endsWith('.webp')) mimeType = 'image/webp';
            else if (name.endsWith('.gif')) mimeType = 'image/gif';
            else if (name.endsWith('.bmp')) mimeType = 'image/bmp';
            else if (name.endsWith('.tif') || name.endsWith('.tiff')) mimeType = 'image/tiff';
            else mimeType = 'image/jpeg';
        }

        requestBody = {
            contents: [{
                parts: [
                    { text: "Extract any sensitive text or data from this image and then analyze it. " + prompt },
                    { inlineData: { data: base64Data, mimeType: mimeType } }
                ]
            }],
            generationConfig: { temperature: 0.2, maxOutputTokens: 1500 }
        };
    } else {
        requestBody = {
            contents: [{ parts: [{ text: prompt + "\n\nFILE CONTENT:\n```\n" + contentSample + "\n```" }] }],
            generationConfig: { temperature: 0.2, maxOutputTokens: 1500 }
        };
    }

    try {
        const url = `${GEMINI_API_URL}/${GEMINI_MODEL}:generateContent`;

        const response = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
            body: JSON.stringify(requestBody),
        });

        if (!response.ok) {
            const errText = await response.text();
            console.warn("Gemini API error:", response.status, errText);
            return {
                enabled: true,
                error: `API error: ${response.status}`,
                fallback: true,
            };
        }

        const result = await response.json();

        // Extract text from Gemini response
        if (result.candidates && result.candidates.length > 0) {
            const textContent = result.candidates[0].content.parts[0].text;

            // Parse JSON from response (handle markdown code blocks)
            const jsonStr = extractJSON(textContent);
            try {
                const analysis = JSON.parse(jsonStr);
                return {
                    enabled: true,
                    ...analysis,
                    model: GEMINI_MODEL,
                    analyzed_at: new Date().toISOString(),
                };
            } catch (parseErr) {
                console.warn("Failed to parse AI response:", parseErr, textContent);
                return {
                    enabled: true,
                    error: "Failed to parse AI response",
                    raw_response: textContent.substring(0, 500),
                    fallback: true,
                };
            }
        }

        return { enabled: true, error: "Empty AI response", fallback: true };

    } catch (err) {
        console.warn("AI analysis error:", err);
        return {
            enabled: true,
            error: err.message,
            fallback: true,
        };
    }
}

/**
 * Extract JSON from a response that might contain markdown code fences.
 */
function extractJSON(text) {
    // Try to find JSON in code blocks first
    const codeBlockMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
    if (codeBlockMatch) {
        return codeBlockMatch[1].trim();
    }

    // Find raw JSON object
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}") + 1;
    if (start >= 0 && end > start) {
        return text.substring(start, end);
    }

    return "{}";
}

/**
 * Merge regex findings with AI analysis into a unified result.
 */
function mergeAnalysis(regexResult, aiResult) {
    // If AI is disabled or errored, just return regex result
    if (!aiResult || !aiResult.enabled || aiResult.error) {
        return {
            ...regexResult,
            ai_analysis: aiResult || { enabled: false },
        };
    }

    // Determine the highest severity between regex and AI
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };

    const regexSeverity = severityOrder[regexResult.severity] || 0;
    const aiSeverity = severityOrder[aiResult.risk_level] || 0;

    // AI can upgrade severity but we also respect regex findings
    const finalSeverity = aiSeverity > regexSeverity
        ? aiResult.risk_level
        : regexResult.severity;

    // Determine action: AI can upgrade from allow→warn or warn→block
    let finalAction = regexResult.action;
    if (aiResult.should_block && finalAction !== "block") {
        finalAction = "block";
    } else if (aiResult.recommendation === "WARN" && finalAction === "allow") {
        finalAction = "warn";
    } else if (aiResult.recommendation === "BLOCK") {
        finalAction = "block";
    }

    // Merge AI findings into the findings list
    const aiFindings = (aiResult.findings || []).map(f => ({
        pattern_name: `AI: ${f.type}`,
        description: f.description,
        category: f.type,
        matched_text: f.evidence || "[AI detected]",
        severity: f.severity,
        confidence: aiResult.risk_score / 100,
        line_number: 0,
        context: f.description,
        source: "ai",
    }));

    return {
        ...regexResult,
        severity: finalSeverity,
        action: finalAction,
        findings: [...(regexResult.findings || []), ...aiFindings],
        findingCount: (regexResult.findingCount || 0) + aiFindings.length,
        ai_analysis: {
            enabled: true,
            risk_level: aiResult.risk_level,
            risk_score: aiResult.risk_score,
            should_block: aiResult.should_block,
            categories: aiResult.categories,
            context_analysis: aiResult.context_analysis,
            recommendation: aiResult.recommendation,
            reasoning: aiResult.reasoning,
            model: aiResult.model,
            finding_count: aiFindings.length,
        },
    };
}

// Export
if (typeof globalThis !== "undefined") {
    globalThis.TronAI = {
        redactForLLM,
        analyzeWithAI,
        mergeAnalysis,
        extractJSON,
    };
}
