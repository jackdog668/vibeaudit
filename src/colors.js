/**
 * Zero-dependency ANSI terminal colors.
 * No chalk, no picocolors — just escape codes.
 */

const SUPPORTS_COLOR =
  process.env.FORCE_COLOR !== '0' &&
  (process.env.FORCE_COLOR === '1' ||
    process.stdout.isTTY ||
    process.env.CI === 'true');

function wrap(code, resetCode) {
  if (!SUPPORTS_COLOR) return (str) => str;
  return (str) => `\x1b[${code}m${str}\x1b[${resetCode}m`;
}

export const bold = wrap('1', '22');
export const dim = wrap('2', '22');
export const red = wrap('31', '39');
export const green = wrap('32', '39');
export const yellow = wrap('33', '39');
export const cyan = wrap('36', '39');
export const gray = wrap('90', '39');
export const bgRed = wrap('41', '49');
export const bgYellow = wrap('43', '49');
export const bgGreen = wrap('42', '49');
