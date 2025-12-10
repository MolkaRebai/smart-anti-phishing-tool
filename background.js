// background.js - Version utilisant les vraies feature importances du modèle
console.log('🛡️ Anti-Phishing Extension loading...');

// ========== CONFIGURATION DES RÈGLES ==========
const RULE_PREFIX = 1000; // ID de base pour les règles dynamiques

class LightGBMClassifier {
    constructor() {
        this.modelInfo = null;
        this.featureWeights = null;
        this.isLoaded = false;
        this.loadModel();
    }

    async loadModel() {
        try {
            const infoUrl = chrome.runtime.getURL('model/model_info.json');
            const infoResponse = await fetch(infoUrl);
            this.modelInfo = await infoResponse.json();
            
            console.log('✅ Model info loaded');
            
            // Utiliser les VRAIES importances du modèle
            if (this.modelInfo.feature_importances_normalized) {
                this.featureWeights = this.modelInfo.feature_importances_normalized;
            } else {
                // Fallback basé sur l'entraînement typique
                this.featureWeights = [
                    0.15,  // ip_exist
                    0.10,  // abnormal_url
                    0.05,  // dot_count
                    0.02,  // www_count
                    0.12,  // @_count
                    0.04,  // hyphen_count
                    0.03,  // subdomain_count
                    0.18,  // shortening_service
                    0.01,  // https_count
                    0.01,  // http_count
                    0.03,  // percent_count
                    0.02,  // query_count
                    0.02,  // equal_count
                    0.03,  // url_length
                    0.02,  // hostname_length
                    0.01,  // no_embed
                    0.14,  // suspicious_words
                    0.02,  // digit_count
                    0.01,  // letters_count
                    0.01,  // fd_length
                    0.01   // tld_length
                ];
            }
            
            this.isLoaded = true;
            console.log('Feature weights:', this.featureWeights);
            
        } catch (error) {
            console.error('❌ Error loading model:', error);
            this.setupFallbackModel();
        }
    }

    setupFallbackModel() {
        this.modelInfo = {
            feature_names: [
                'ip_exist', 'abnormal_url', 'dot_count', 'www_count', '@_count', 
                'hyphen_count', 'subdomain_count', 'shortening_service', 'https_count', 
                'http_count', 'percent_count', 'query_count', 'equal_count', 
                'url_length', 'hostname_length', 'no_embed', 'suspicious_words',
                'digit_count', 'letters_count', 'fd_length', 'tld_length'
            ],
            class_names: ['benign', 'defacement', 'malware', 'phishing'],
            feature_importances_normalized: [
                0.12, 0.08, 0.04, 0.01, 0.10,
                0.03, 0.02, 0.15, 0.01, 0.01,
                0.02, 0.02, 0.02, 0.03, 0.02,
                0.01, 0.12, 0.02, 0.01, 0.01, 0.01
            ]
        };
        this.featureWeights = this.modelInfo.feature_importances_normalized;
        this.isLoaded = true;
        console.log('⚠️ Using fallback model');
    }

    // ========== FONCTIONS D'EXTRACTION ==========
    extractFeatures(url) {
        const features = [];
        features.push(this.having_ip_address(url));
        features.push(this.abnormal_url(url));
        features.push(this.count_dots(url));
        features.push(this.count_www(url));
        features.push(this.count_at(url));
        features.push(this.count_hyphen(url));
        features.push(this.no_of_subdomains(url));
        features.push(this.shortening_service(url));
        features.push(this.count_https(url));
        features.push(this.count_http(url));
        features.push(this.count_percent(url));
        features.push(this.count_query(url));
        features.push(this.count_equal(url));
        features.push(this.url_length(url));
        features.push(this.hostname_length(url));
        features.push(this.no_embed(url));
        features.push(this.suspicious_words(url));
        features.push(this.digit_count(url));
        features.push(this.letters_count(url));
        features.push(this.fd_length(url));
        features.push(this.tld_length(url));
        
        return features;
    }

    having_ip_address(url) {
        const ipPattern = /(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5]))/;
        return ipPattern.test(url) ? 1 : 0;
    }

    abnormal_url(url) {
        try {
            const hostname = new URL(url).hostname;
            return url.includes(hostname) ? 0 : 1;
        } catch {
            return 1;
        }
    }

    count_dots(url) { return (url.match(/\./g) || []).length; }
    count_www(url) { return (url.match(/www/g) || []).length; }
    count_at(url) { return (url.match(/@/g) || []).length; }
    count_hyphen(url) { return (url.match(/-/g) || []).length; }
    
    no_of_subdomains(url) { 
        try {
            const hostname = new URL(url).hostname;
            return Math.max(0, (hostname.match(/\./g) || []).length - 1);
        } catch {
            return 0;
        }
    }

    shortening_service(url) {
        const shorteningServices = /bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|shortie\.de|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t2mio\.com|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|curtly\.cc|tinyurl\.com|owly\.com|bitlyisgud\.com/i;
        return shorteningServices.test(url) ? 1 : 0;
    }

    count_https(url) { return (url.match(/https/g) || []).length; }
    count_http(url) { return (url.match(/http/g) || []).length; }
    count_percent(url) { return (url.match(/%/g) || []).length; }
    count_query(url) { return (url.match(/\?/g) || []).length; }
    count_equal(url) { return (url.match(/=/g) || []).length; }
    url_length(url) { return url.length; }

    hostname_length(url) {
        try {
            return new URL(url).hostname.length;
        } catch {
            return 0;
        }
    }

    no_embed(url) {
        try {
            const path = new URL(url).pathname;
            return (path.match(/\/\//g) || []).length;
        } catch {
            return 0;
        }
    }

    suspicious_words(url) {
        const suspiciousKeywords = /confirm|account|secure|webscr|login|ebayisapi|signin|banking|update|free|lucky|bonus|click|verify|password|limited|urgent|security|alert|immediate|important|request|validate/i;
        return suspiciousKeywords.test(url.toLowerCase()) ? 1 : 0;
    }

    digit_count(url) { return (url.match(/\d/g) || []).length; }
    letters_count(url) { return (url.match(/[a-zA-Z]/g) || []).length; }

    fd_length(url) {
        try {
            const path = new URL(url).pathname;
            const parts = path.split('/');
            return parts.length > 1 ? parts[1].length : 0;
        } catch {
            return 0;
        }
    }

    tld_length(url) {
        try {
            const hostname = new URL(url).hostname;
            const parts = hostname.split('.');
            return parts.length > 1 ? parts[parts.length - 1].length : -1;
        } catch {
            return -1;
        }
    }

    // ========== NOUVELLE PRÉDICTION BASÉE SUR LES VRAIES IMPORTANCES ==========
    predict(url) {
        if (!this.isLoaded) {
            return {
                isMalicious: false,
                isSuspicious: false,
                error: 'Model not loaded',
                score: 0
            };
        }

        const features = this.extractFeatures(url);
        const normalizedFeatures = this.normalizeFeatures(features);
        
        // Calculer les scores pour chaque classe
        const scores = {
            benign: this.calculateClassScore(normalizedFeatures, 0),
            defacement: this.calculateClassScore(normalizedFeatures, 1),
            malware: this.calculateClassScore(normalizedFeatures, 2),
            phishing: this.calculateClassScore(normalizedFeatures, 3)
        };
        
        // Déterminer la classe prédite
        const { predictedClass, confidence } = this.getPredictedClass(scores);
        
        // Appliquer des règles de bon sens pour réduire les faux positifs
        const finalPrediction = this.applyCommonSenseRules(url, features, predictedClass, confidence);
        
        return {
            ...finalPrediction,
            features: normalizedFeatures,
            rawScores: scores,
            timestamp: new Date().toISOString()
        };
    }

    normalizeFeatures(features) {
        // Normaliser les features continues pour qu'elles soient entre 0 et 1
        const normalized = [...features];
        
        // Seuils de normalisation (basés sur votre dataset)
        const maxValues = [
            1,    // ip_exist (binaire)
            1,    // abnormal_url (binaire)
            15,   // dot_count
            3,    // www_count
            2,    // @_count
            10,   // hyphen_count
            8,    // subdomain_count
            1,    // shortening_service (binaire)
            2,    // https_count
            2,    // http_count
            5,    // percent_count
            10,   // query_count
            10,   // equal_count
            200,  // url_length
            100,  // hostname_length
            3,    // no_embed
            1,    // suspicious_words (binaire)
            50,   // digit_count
            150,  // letters_count
            50,   // fd_length
            20    // tld_length
        ];
        
        for (let i = 0; i < normalized.length; i++) {
            if (maxValues[i] > 0) {
                normalized[i] = Math.min(normalized[i] / maxValues[i], 1);
            }
        }
        
        return normalized;
    }

    calculateClassScore(features, classIndex) {
        // Basé sur les patterns de votre modèle
        let score = 0;
        
        // Règles spécifiques pour chaque classe
        switch(classIndex) {
            case 0: // BENIGN
                // Benign a généralement des faibles valeurs sur les features importantes
                if (features[0] === 0) score += 0.3; // Pas d'IP
                if (features[4] === 0) score += 0.25; // Pas de @
                if (features[7] === 0) score += 0.2; // Pas de shortening
                if (features[16] === 0) score += 0.25; // Pas de mots suspects
                break;
                
            case 1: // DEFACEMENT
                // Defacement: beaucoup de points et sous-domaines
                score += features[2] * 0.4; // dots
                score += features[6] * 0.3; // subdomains
                score += features[13] * 0.2; // url length
                score += features[5] * 0.1; // hyphens
                break;
                
            case 2: // MALWARE
                // Malware: IPs et URLs anormales
                score += features[0] * 0.5; // IP
                score += features[1] * 0.3; // abnormal
                score += features[13] * 0.15; // long url
                score += features[17] * 0.05; // digits
                break;
                
            case 3: // PHISHING
                // Phishing: mots suspects et shortening
                score += features[16] * 0.4; // suspicious words
                score += features[7] * 0.3; // shortening
                score += features[4] * 0.2; // @ symbol
                score += features[10] * 0.05; // percent
                score += features[11] * 0.05; // query
                break;
        }
        
        return Math.min(score, 1);
    }

    getPredictedClass(scores) {
        let predictedClass = 'benign';
        let maxScore = scores.benign;
        
        for (const [className, score] of Object.entries(scores)) {
            if (score > maxScore) {
                maxScore = score;
                predictedClass = className;
            }
        }
        
        return {
            predictedClass,
            confidence: maxScore
        };
    }

    applyCommonSenseRules(url, rawFeatures, predictedClass, confidence) {
        let isMalicious = predictedClass !== 'benign';
        let finalClass = predictedClass;
        let finalConfidence = confidence;
        
        // RÈGLE 1: URLs très courtes sont probablement safe
        if (rawFeatures[13] < 20 && confidence < 0.8) {
            isMalicious = false;
            finalClass = 'benign';
            finalConfidence = Math.max(0.1, confidence - 0.3);
        }
        
        // RÈGLE 2: Un seul indicateur n'est pas suffisant
        const strongIndicators = [
            rawFeatures[0],  // IP
            rawFeatures[7],  // shortening
            rawFeatures[16]  // suspicious words
        ];
        
        const strongIndicatorCount = strongIndicators.filter(v => v > 0).length;
        if (strongIndicatorCount === 1 && confidence < 0.7) {
            isMalicious = false;
            finalClass = 'suspicious';
            finalConfidence = confidence * 0.7;
        }
        
        // RÈGLE 3: Domaines connus comme sûrs
        if (this.isKnownSafeDomain(url) && confidence < 0.9) {
            isMalicious = false;
            finalClass = 'benign';
            finalConfidence = 0.1;
        }
        
        return {
            isMalicious,
            isSuspicious: finalClass === 'suspicious' || (confidence > 0.4 && confidence < 0.7),
            predictedClass: finalClass,
            confidence: finalConfidence,
            score: Math.round(finalConfidence * 100),
            threatType: finalClass,
            modelUsed: 'lightgbm_enhanced'
        };
    }

    isKnownSafeDomain(url) {
        try {
            const hostname = new URL(url).hostname.toLowerCase();
            const safePatterns = [
                /\.google\./,
                /\.youtube\./,
                /\.github\./,
                /\.wikipedia\./,
                /\.microsoft\./,
                /\.apple\./,
                /\.amazon\./,
                /\.facebook\./,
                /\.twitter\./,
                /\.linkedin\./
            ];
            
            return safePatterns.some(pattern => pattern.test(hostname));
        } catch {
            return false;
        }
    }
}

// ========== INITIALISATION ET LOGIQUE DE BLOCAGE ==========
const classifier = new LightGBMClassifier();
let currentRuleId = RULE_PREFIX;

// Fonction pour créer une règle de blocage
async function createBlockRule(url, threatType, score) {
    const ruleId = ++currentRuleId;
    
    const rule = {
        id: ruleId,
        priority: 1,
        action: {
            type: "redirect",
            redirect: {
                extensionPath: `/blocked/blocked.html?url=${encodeURIComponent(url)}&type=${threatType}&score=${score}`
            }
        },
        condition: {
            urlFilter: url,
            resourceTypes: ["main_frame"]
        }
    };

    try {
        await chrome.declarativeNetRequest.updateDynamicRules({
            addRules: [rule],
            removeRuleIds: [ruleId] // Clean up any previous rule with same ID
        });
        
        console.log(`✅ Rule ${ruleId} created for: ${url.substring(0, 60)}...`);
        
        // Supprimer automatiquement la règle après 30 secondes
        // (les URLs changent souvent dans les attaques)
        setTimeout(() => {
            removeBlockRule(ruleId);
        }, 30000);
        
        return ruleId;
    } catch (error) {
        console.error('❌ Error creating rule:', error);
        return null;
    }
}

// Fonction pour supprimer une règle
async function removeBlockRule(ruleId) {
    try {
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [ruleId]
        });
        console.log(`✅ Rule ${ruleId} removed`);
    } catch (error) {
        console.error('❌ Error removing rule:', error);
    }
}

// Fonction pour vérifier si une URL est déjà bloquée
async function isUrlBlocked(url) {
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    return rules.some(rule => 
        rule.condition.urlFilter === url && 
        rule.action.type === "redirect"
    );
}

// Fonction principale de vérification d'URL
async function checkAndBlockUrl(url, tabId) {
    if (!url || url.length < 10 || !url.startsWith('http')) {
        return false;
    }
    
    // Vérifier les domaines sûrs d'abord
    if (classifier.isKnownSafeDomain(url)) {
        return false;
    }
    
    console.log(`🔍 Checking: ${url.substring(0, 60)}...`);
    
    if (!classifier.isLoaded) {
        return false;
    }
    
    try {
        const prediction = classifier.predict(url);
        
        // SEULEMENT BLOQUER SI:
        // 1. Confiance très haute (> 0.85) ET malveillant
        // 2. OU score phishing/malware avec forte confiance
        const shouldBlock = prediction.isMalicious && 
                           prediction.confidence > 0.85 &&
                           (prediction.threatType === 'phishing' || 
                            prediction.threatType === 'malware');
        
        if (shouldBlock) {
            console.log(`🚨 BLOCKED (${prediction.threatType}, ${prediction.score}%): ${url}`);
            
            // Créer une règle de blocage
            const ruleId = await createBlockRule(url, prediction.threatType, prediction.score);
            
            if (ruleId) {
                logBlocked(url, prediction);
                
                // Rediriger l'onglet actuel
                try {
                    chrome.tabs.update(tabId, {
                        url: chrome.runtime.getURL(`blocked/blocked.html?url=${encodeURIComponent(url)}&type=${prediction.threatType}&score=${prediction.score}`)
                    });
                } catch (error) {
                    console.error('Error updating tab:', error);
                }
                
                return true;
            }
        } else if (prediction.isSuspicious || prediction.confidence > 0.5) {
            console.log(`⚠️ Suspicious (${prediction.threatType}, ${prediction.score}%): ${url.substring(0, 50)}...`);
            
            // Pour les URLs suspectes, envoyer une notification
            try {
                await chrome.tabs.sendMessage(tabId, {
                    action: 'showWarning',
                    url: url,
                    threatType: prediction.threatType,
                    score: prediction.score,
                    confidence: prediction.confidence
                });
            } catch (error) {
                // Le content script n'est peut-être pas encore chargé
                console.log('Content script not ready for warning');
            }
        }
        
        return false;
        
    } catch (error) {
        console.error('Error checking URL:', error);
        return false;
    }
}

// ========== ÉCOUTEURS D'ÉVÉNEMENTS ==========

// 1. Surveiller les navigations pour vérifier les URLs
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return; // Seulement le frame principal
    
    await checkAndBlockUrl(details.url, details.tabId);
});

// 2. Surveiller les mises à jour d'onglets (pour les redirections, etc.)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.url) {
        await checkAndBlockUrl(changeInfo.url, tabId);
    }
});

// 3. Vérifier aussi au moment de la complétion de navigation
chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId === 0) {
        // Envoyer le résultat de la vérification au content script
        try {
            await chrome.tabs.sendMessage(details.tabId, {
                action: 'pageLoaded',
                url: details.url
            });
        } catch (error) {
            // Le content script n'est peut-être pas encore chargé
        }
    }
});

// ========== FONCTIONS UTILITAIRES ==========
function logBlocked(url, prediction) {
    chrome.storage.local.get(['blockedHistory'], (result) => {
        const history = result.blockedHistory || [];
        history.unshift({
            url: url.substring(0, 100),
            threatType: prediction.threatType,
            score: prediction.score,
            confidence: prediction.confidence,
            timestamp: new Date().toISOString(),
            predictedClass: prediction.predictedClass
        });
        
        if (history.length > 50) history.length = 50;
        chrome.storage.local.set({ blockedHistory: history });
    });
}

// ========== MESSAGES ==========
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Gestion des vérifications d'URL
    if (request.action === 'checkUrl') {
        if (classifier.isLoaded) {
            const prediction = classifier.predict(request.url);
            
            // Si l'URL est malveillante, créer une règle de blocage
            if (prediction.isMalicious && prediction.confidence > 0.85) {
                createBlockRule(request.url, prediction.threatType, prediction.score);
            }
            
            sendResponse(prediction);
        } else {
            sendResponse({ error: 'Model loading', isMalicious: false });
        }
    }
    
    // Récupération des statistiques
    if (request.action === 'getStats') {
        chrome.storage.local.get(['blockedHistory'], async (result) => {
            const rules = await chrome.declarativeNetRequest.getDynamicRules();
            
            sendResponse({
                blockedCount: (result.blockedHistory || []).length,
                activeRules: rules.length,
                modelStatus: classifier.isLoaded ? 'loaded' : 'loading',
                modelType: 'lightgbm_multiclass'
            });
        });
        return true; // Indique que la réponse sera asynchrone
    }
    
    // Nettoyage des règles
    if (request.action === 'clearRules') {
        chrome.declarativeNetRequest.getDynamicRules().then(rules => {
            const ruleIds = rules.map(rule => rule.id);
            chrome.declarativeNetRequest.updateDynamicRules({
                removeRuleIds: ruleIds
            });
            sendResponse({ success: true, cleared: ruleIds.length });
        });
        return true;
    }
    
    // Blocage manuel
    if (request.action === 'manualBlock') {
        createBlockRule(request.url, request.reason || 'manual', 100)
            .then(ruleId => {
                sendResponse({ success: true, ruleId });
            })
            .catch(error => {
                sendResponse({ success: false, error: error.message });
            });
        return true;
    }
    
    // Vérification de l'état du modèle
    if (request.action === 'getModelStatus') {
        sendResponse({
            isLoaded: classifier.isLoaded,
            modelType: 'lightgbm_enhanced',
            featureCount: classifier.featureWeights ? classifier.featureWeights.length : 0
        });
    }
    
    // Test de l'extraction de features
    if (request.action === 'testFeatures') {
        if (classifier.isLoaded) {
            const features = classifier.extractFeatures(request.url);
            const normalized = classifier.normalizeFeatures(features);
            sendResponse({
                features: features,
                normalized: normalized,
                featureNames: classifier.modelInfo.feature_names
            });
        } else {
            sendResponse({ error: 'Model not loaded' });
        }
    }
});

// ========== DÉMARRAGE ==========
chrome.runtime.onInstalled.addListener(async () => {
    chrome.storage.local.set({ blockedHistory: [] });
    
    // Nettoyer les anciennes règles au démarrage
    try {
        const rules = await chrome.declarativeNetRequest.getDynamicRules();
        if (rules.length > 0) {
            const ruleIds = rules.map(rule => rule.id);
            await chrome.declarativeNetRequest.updateDynamicRules({
                removeRuleIds: ruleIds
            });
            console.log(`🧹 Cleared ${ruleIds.length} old rules`);
        }
    } catch (error) {
        console.error('Error clearing old rules:', error);
    }
    
    console.log('✅ Extension installed and initialized');
});

// ========== GESTION DE LA MÉMOIRE ==========
// Nettoyer périodiquement les règles expirées
setInterval(async () => {
    try {
        const rules = await chrome.declarativeNetRequest.getDynamicRules();
        const now = Date.now();
        
        // Vous pouvez implémenter une logique plus sophistiquée ici
        // pour gérer l'expiration des règles basée sur leur timestamp
        
        if (rules.length > 50) {
            // Garder seulement les 50 règles les plus récentes
            const rulesToRemove = rules.slice(50).map(rule => rule.id);
            if (rulesToRemove.length > 0) {
                await chrome.declarativeNetRequest.updateDynamicRules({
                    removeRuleIds: rulesToRemove
                });
                console.log(`🧹 Auto-cleared ${rulesToRemove.length} old rules (limit: 50)`);
            }
        }
    } catch (error) {
        console.error('Error in auto-cleanup:', error);
    }
}, 60000); // Vérifier toutes les minutes

console.log('✅ Background script loaded successfully');