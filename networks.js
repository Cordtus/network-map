// Supported networks. Each entry maps a stable slug to its display name and
// the chain-registry name used to seed a crawl (`--chain <chainName>`).
// Per-network data lives in data/<slug>/ (geolocations.js, insights.json, nodes.csv).
window.SUPPORTED_NETWORKS = [
    { slug: "secretnetwork", name: "Secret Network", chainName: "secretnetwork" },
    { slug: "nomic", name: "Nomic", chainName: "nomic" },
    { slug: "genesisl1", name: "GenesisL1", chainName: "genesisl1" },
];

window.findNetwork = function (slug) {
    return window.SUPPORTED_NETWORKS.find(n => n.slug === slug) || null;
};

// Strip the leading ASN from a geolocation org string ("AS16276 OVH SAS" -> "OVH SAS").
window.providerName = function (org) {
    if (!org) return null;
    const s = String(org).trim();
    return /^AS\d+\s+/.test(s) ? s.replace(/^AS\d+\s+/, "") : s;
};

// Current network: ?network= param wins, else the persisted selection, else
// the first supported network. The param is persisted for later visits.
window.currentNetwork = function () {
    const param = new URLSearchParams(location.search).get("network");
    const fromParam = param && window.findNetwork(param);
    if (fromParam) {
        localStorage.setItem("map-network", fromParam.slug);
        return fromParam;
    }
    return window.findNetwork(localStorage.getItem("map-network")) || window.SUPPORTED_NETWORKS[0];
};

// Persist a network selection and navigate to it.
window.setNetwork = function (slug) {
    const n = window.findNetwork(slug);
    if (!n) return;
    localStorage.setItem("map-network", n.slug);
    const url = new URL(location.href);
    url.searchParams.set("network", n.slug);
    location.href = url.href;
};

// Make the Map/Insights tab links carry the current network so switching pages
// keeps the selection.
window.bindNetworkTabs = function (net) {
    document.querySelectorAll("a.tab").forEach(a => {
        const href = a.getAttribute("href") || "";
        if (/\.html$/.test(href)) {
            a.href = href.split("?")[0] + "?network=" + net.slug;
        }
    });
};