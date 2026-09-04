// Supported networks. Each entry maps a stable slug to its display name and
// the chain-registry name used to seed a crawl (`--chain <chainName>`).
// Per-network data lives in data/<slug>/ (geolocations.js, insights.json, nodes.csv).
window.SUPPORTED_NETWORKS = [
    { slug: "secretnetwork", name: "Secret Network", chainName: "secretnetwork" },
    { slug: "nomic", name: "Nomic", chainName: "nomic" },
];

window.findNetwork = function (slug) {
    return window.SUPPORTED_NETWORKS.find(n => n.slug === slug) || null;
};

// Current network from the ?network= query param (default: first supported).
window.currentNetwork = function () {
    const slug = new URLSearchParams(location.search).get("network");
    return window.findNetwork(slug) || window.SUPPORTED_NETWORKS[0];
};