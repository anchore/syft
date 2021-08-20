/**
 * Collapse whitespace to a single space.
 *
 * @param {string} value
 * @returns {string}
 */
export function collapseWhiteSpace(value) {
  return String(value).replace(/\s+/g, ' ')
}
