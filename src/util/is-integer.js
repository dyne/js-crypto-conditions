export default function (value) {
  return typeof value === 'number' &&
    isFinite(value) &&
    Math.floor(value) === value
}
