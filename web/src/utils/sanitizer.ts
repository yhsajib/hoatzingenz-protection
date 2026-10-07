/**
 * Security & Input Sanitization Utility for HoatzinGenz Protection
 * Protects against XSS, SQLi, Path Traversal, and Malicious Injection.
 */

export function sanitizeInput(input: string): string {
  if (!input) return '';
  return input
    .trim()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

export function sanitizePath(pathStr: string): string {
  if (!pathStr) return '';
  // Remove directory traversal sequences and null bytes
  return pathStr
    .replace(/\x00/g, '')
    .replace(/\.\.[/\\]/g, '')
    .replace(/[/\\]\.\./g, '');
}

export function validateUsername(username: string): { valid: boolean; message?: string } {
  if (!username || username.trim().length < 3) {
    return { valid: false, message: 'Username must be at least 3 characters long.' };
  }
  if (username.length > 30) {
    return { valid: false, message: 'Username cannot exceed 30 characters.' };
  }
  const usernameRegex = /^[a-zA-Z0-9_-]+$/;
  if (!usernameRegex.test(username)) {
    return { valid: false, message: 'Username can only contain letters, numbers, underscores, and hyphens.' };
  }
  return { valid: true };
}

export function validateEmail(email: string): boolean {
  if (!email) return false;
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email.trim());
}

export function validatePasswordStrength(password: string): { score: number; label: string; strongEnough: boolean } {
  if (!password) return { score: 0, label: 'Empty', strongEnough: false };
  let score = 0;
  if (password.length >= 8) score += 25;
  if (password.length >= 12) score += 15;
  if (/[A-Z]/.test(password)) score += 20;
  if (/[a-z]/.test(password)) score += 15;
  if (/[0-9]/.test(password)) score += 15;
  if (/[^A-Za-z0-9]/.test(password)) score += 10;

  let label = 'Weak';
  if (score >= 80) label = 'Strong';
  else if (score >= 50) label = 'Moderate';

  return {
    score,
    label,
    strongEnough: score >= 50,
  };
}