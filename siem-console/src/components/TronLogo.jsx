// Tron mark: a hexagonal boundary (the protected perimeter) with a circuit-trace "T"
// whose stem terminates in an inspection node. Drawn with currentColor so it adapts to
// the tile it sits on.
const TronLogo = ({ size = 20, title = 'Tron', ...rest }) => (
  <svg width={size} height={size} viewBox="0 0 64 64" fill="none" role="img" aria-label={title} {...rest}>
    <path d="M32 5.5 54.5 18.5v27L32 58.5 9.5 45.5v-27z" stroke="currentColor" strokeWidth="4.5" strokeLinejoin="round" />
    <path d="M19 22h26" stroke="currentColor" strokeWidth="5" strokeLinecap="round" />
    <path d="M32 22v15" stroke="currentColor" strokeWidth="5" strokeLinecap="round" />
    <path d="M19 22v7M45 22v7" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    <circle cx="19" cy="31.5" r="2.6" fill="currentColor" />
    <circle cx="45" cy="31.5" r="2.6" fill="currentColor" />
    <circle cx="32" cy="43.5" r="4.6" fill="currentColor" />
  </svg>
);

export default TronLogo;
