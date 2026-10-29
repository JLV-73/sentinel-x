"""Pure, offline rules over parent-produced, strictly typed derived facts.

No raw headers, HTML, cookies, URLs, markers or certificate data are accepted or
returned. A True/False fact is meaningful only with its accompanying complete
flag exactly True. The caller must parse responses in an isolated, bounded layer;
it must set complete False on errors, blocking, quota exhaustion or truncation.
Never infer a negative fact from a failed, partial or unperformed observation.

API: evaluate_findings(facts, *, route, method, date, language='en') -> list[dict].
Facts are caller-attested derived data; this module cannot verify a producer or
transport. Do not use without validating that boundary. For CORS require typed
origin_tested and same_endpoint flags, a matching acao/kind enum (wildcard,
reflected, none), observed consistent with kind, and a boolean credentials
header result. These facts describe one completed controlled-origin request.
Redirect/reflection require performed and authorized-parameter flags plus
witness_checked/destination_followed or marker_checked respectively. A positive
redirect additionally requires caller-attested independent completed control on the
same endpoint, changing only the authorized parameter, without a witness match:
control_complete, control_same_endpoint, control_parameter_changed_only are True,
and control_witness_match is False. This module cannot verify those attestations.
Cookies
require an integer cookie_count from 1 through 10000. Any explicit state other
than 'completed' is indeterminate. Advisory matching is unavailable and always
indeterminate. The caller must attest each supplied field truthfully.
For scripts observed=True means an actual parsed HTML script src has a different
origin; for directory_index True requires exact recognized index markers, not
mere directory-like words. version True requires an explicitly declared exact
product/version independently mapped reliably; no banners or CVE inference.
Cookies observed=True means at least one observed cookie lacks Secure, HttpOnly
or an appropriate SameSite attribute; an empty cookie set must be complete=False.
For headers True means the corresponding protection is present and valid under
caller policy, not merely that a header name is present. HTTPS/TLS True requires
successful verified TLS, never a bypass. Generic booleans are deliberately not
raw transport evidence. The context of reflection is an optional enum: html_text,
html_attribute, script, other, unknown; no arbitrary values are copied.
Route paths may themselves contain personal data: only '/' survives; all others
are redacted. The caller can associate findings to its own authorized route by
out-of-band index. language selects fixed English or French prose; identifiers,
status enums, technical source tokens and reference URLs remain unchanged.
"""
from datetime import date as _date

CONDITIONS = {
    'https_tls': 'verified HTTPS and TLS',
    'hsts': 'valid HSTS',
    'csp': 'a valid Content Security Policy',
    'x_content_type_options': 'nosniff protection',
    'referrer_policy': 'a valid Referrer-Policy',
    'permissions_policy': 'a valid Permissions-Policy',
    'cookie_attributes': 'a cookie missing a recommended attribute',
    'third_party_scripts': 'a third-party script tag',
    'version': 'a reliable explicit component version',
    'debug_info': 'an explicit debug information indicator',
    'directory_index': 'an exact directory index marker',
    'cors': 'a permissive CORS response',
    'redirect': 'an exact non-followed witness redirect',
    'reflection': 'an inert marker reflection',
}


def evaluate_findings(facts, *, route, method, date, language='en'):
    """Return ordered, privacy-preserving findings; no I/O or clock reads."""
    facts = facts if isinstance(facts, dict) else {}
    safe_route = '/' if route == '/' else '[redacted route]'
    safe_method = method if method in ('GET', 'HEAD', 'OPTIONS') else 'UNKNOWN'
    try:
        safe_date = _date.fromisoformat(date).isoformat() if isinstance(date, str) else 'unknown'
    except ValueError:
        safe_date = 'unknown'
    results = []
    for name, condition in CONDITIONS.items():
        finding = dict(id=name, status='indeterminate', severity='unknown',
                       reason='Observation was not completed.', evidence='No reliable observation.',
                       limitations='This check does not establish overall security.',
                       preconditions='An authorized, complete observation is required.',
                       recommendation='Repeat only within the authorized scope.',
                       reference='https://cheatsheetseries.owasp.org/', method=safe_method,
                       route=safe_route, date=safe_date)
        fact = facts.get(name)
        if name == 'version':
            finding['reason'] = 'Advisory assessment is unavailable.'
            finding['limitations'] = 'No advisory matching or vulnerability conclusion was performed.'
            results.append(finding)
            continue
        if (not isinstance(fact, dict) or fact.get('complete') is not True or
                ('state' in fact and fact['state'] != 'completed')):
            results.append(finding)
            continue
        observed = fact.get('observed')
        if name == 'https_tls' and observed is not True:
            results.append(finding)
            continue
        if name in ('redirect', 'reflection'):
            valid = fact.get('probe_performed') is True and fact.get('parameter_authorized') is True
            if name == 'redirect':
                valid = valid and fact.get('witness_checked') is True and fact.get('destination_followed') is False
                if observed is True:
                    valid = (valid and fact.get('control_complete') is True and
                             fact.get('control_same_endpoint') is True and
                             fact.get('control_parameter_changed_only') is True and
                             fact.get('control_witness_match') is False)
            else:
                valid = valid and fact.get('marker_checked') is True
            if not valid:
                results.append(finding)
                continue
        count = fact.get('cookie_count')
        if name == 'cookie_attributes' and (type(count) is not int or not 1 <= count <= 10000):
            results.append(finding)
            continue
        if name == 'cors':
            kind = fact.get('kind')
            if (kind not in ('wildcard', 'reflected', 'none') or
                fact.get('origin_tested') is not True or fact.get('same_endpoint') is not True or
                type(fact.get('credentials')) is not bool or type(observed) is not bool or
                observed != (kind != 'none') or fact.get('acao') != kind):
                results.append(finding)
                continue
            status = {'wildcard': 'attention', 'reflected': 'suspected', 'none': 'conformant'}[kind]
            finding['evidence'] = ('Controlled origin tested; ACAO: ' + kind +
                                   '; credentials header true: ' + str(fact['credentials']) + '.')
            finding['limitations'] = 'CORS permissiveness alone does not establish sensitive data exposure.'
            finding['preconditions'] = 'Cross-origin access depends on browser behavior, response content and credentials policy.'
            finding['recommendation'] = 'Review allowed origins and credentials against the intended policy.'
            finding['reference'] = 'https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing/'
        else:
            if type(observed) is not bool or (name == 'version' and not observed):
                results.append(finding)
                continue
            protections = ('https_tls', 'hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy')
            if name in protections:
                status = 'conformant' if observed else 'attention'
            elif name == 'redirect':
                status = 'confirmed' if observed else 'conformant'
            elif name == 'reflection':
                status = 'suspected' if observed else 'conformant'
            else:
                status = 'attention' if observed else 'conformant'
            finding['evidence'] = ('Observed: ' if observed else 'Not observed in the completed check: ') + condition + '.'
            finding['recommendation'] = 'Review this observation against the intended security policy.'
            finding['preconditions'] = 'The supplied derived facts accurately describe the authorized observation.'
            if name == 'version':
                finding['limitations'] = 'No advisory matching or vulnerability conclusion was performed.'
            elif name == 'redirect':
                finding['limitations'] = 'Only the exact witness Location was assessed; the destination was not followed.'
                finding['preconditions'] = 'A designated redirect parameter and an exact matching witness Location are required.'
                finding['reference'] = 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'
            elif name == 'reflection':
                context = fact.get('context')
                if observed and isinstance(context, str) and context in ('html_text', 'html_attribute', 'script', 'other', 'unknown'):
                    finding['evidence'] += ' Context: ' + context + '.'
                finding['limitations'] = 'Inert reflection does not prove XSS or execution.'
                finding['preconditions'] = 'A specifically authorized parameter and an inert marker are required.'
                finding['reference'] = 'https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting/'
            elif name == 'third_party_scripts':
                finding['limitations'] = 'Script origins are declarations only; scripts were not fetched or analyzed.'
            elif name == 'cookie_attributes':
                finding['evidence'] += ' Cookie count: ' + str(count) + '.'
                finding['limitations'] = 'Attributes are assessed without cookie values; applicability depends on cookie use.'
        finding['status'] = status
        finding['severity'] = {'conformant': 'info', 'attention': 'low', 'suspected': 'medium', 'confirmed': 'medium'}[status]
        finding['reason'] = {'conformant': 'The performed check did not identify the specified concern.',
                             'attention': 'The observation merits review.',
                             'suspected': 'The observation warrants investigation but does not prove exploitation.',
                             'confirmed': 'The specified non-destructive behavior was observed.'}[status]
        if name in ('https_tls', 'hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy') and status == 'conformant':
            finding['reason'] = 'The specified protection was observed in this check.'
        results.append(finding)
    for item in results:
        item['evidence'] += ' Method: ' + safe_method + '; date: ' + safe_date + '.'
    if language == 'fr':
        _translate_fr(results)
    return results


def _translate_fr(results):
    conditions = {
        'https_tls': 'HTTPS et TLS vérifiés', 'hsts': 'HSTS valide',
        'csp': 'politique de sécurité du contenu valide',
        'x_content_type_options': 'protection nosniff', 'referrer_policy': 'Referrer-Policy valide',
        'permissions_policy': 'Permissions-Policy valide', 'cookie_attributes': 'cookie sans attribut recommandé',
        'third_party_scripts': 'balise de script tiers', 'version': 'version explicite fiable du composant',
        'debug_info': 'indicateur explicite de débogage', 'directory_index': 'marqueur exact de répertoire',
        'cors': 'réponse CORS permissive', 'redirect': 'redirection exacte vers le témoin non suivie',
        'reflection': 'réflexion du marqueur inerte',
    }
    translations = {
        'Advisory assessment is unavailable.': 'L’évaluation des avis de sécurité est indisponible.',
        'Observation was not completed.': "L’observation n’a pas été achevée.",
        'No reliable observation.': 'Aucune observation fiable.',
        'This check does not establish overall security.': 'Ce contrôle ne démontre pas la sécurité globale.',
        'An authorized, complete observation is required.': 'Une observation autorisée et complète est nécessaire.',
        'Repeat only within the authorized scope.': 'Répéter uniquement dans le périmètre autorisé.',
        'Review this observation against the intended security policy.': 'Examiner cette observation au regard de la politique de sécurité prévue.',
        'The supplied derived facts accurately describe the authorized observation.': 'Les faits dérivés fournis décrivent fidèlement l’observation autorisée.',
        'CORS permissiveness alone does not establish sensitive data exposure.': 'Une politique CORS permissive ne démontre pas à elle seule une exposition de données sensibles.',
        'Cross-origin access depends on browser behavior, response content and credentials policy.': 'L’accès entre origines dépend du navigateur, du contenu de la réponse et de la politique relative aux identifiants.',
        'Review allowed origins and credentials against the intended policy.': 'Vérifier les origines et les identifiants autorisés au regard de la politique prévue.',
        'No advisory matching or vulnerability conclusion was performed.': 'Aucune correspondance avec un avis ni conclusion de vulnérabilité n’a été établie.',
        'Only the exact witness Location was assessed; the destination was not followed.': 'Seul le Location correspondant exactement au témoin a été évalué ; la destination n’a pas été suivie.',
        'A designated redirect parameter and an exact matching witness Location are required.': 'Un paramètre de redirection désigné et un Location correspondant exactement au témoin sont nécessaires.',
        'Inert reflection does not prove XSS or execution.': 'La réflexion inerte ne prouve ni XSS ni exécution.',
        'A specifically authorized parameter and an inert marker are required.': 'Un paramètre expressément autorisé et un marqueur inerte sont nécessaires.',
        'Script origins are declarations only; scripts were not fetched or analyzed.': 'Les origines de scripts sont déclaratives ; les scripts n’ont été ni récupérés ni analysés.',
        'Attributes are assessed without cookie values; applicability depends on cookie use.': 'Les attributs sont évalués sans les valeurs des cookies ; leur pertinence dépend de leur usage.',
        'The performed check did not identify the specified concern.': 'Le contrôle effectué n’a pas identifié le problème considéré.',
        'The observation merits review.': 'L’observation mérite un examen.',
        'The observation warrants investigation but does not prove exploitation.': 'L’observation justifie une investigation mais ne prouve pas une exploitation.',
        'The specified non-destructive behavior was observed.': 'Le comportement non destructif considéré a été observé.',
        'The specified protection was observed in this check.': 'La protection considérée a été observée lors de ce contrôle.',
    }
    for item in results:
        for key in ('reason', 'limitations', 'preconditions', 'recommendation'):
            item[key] = translations.get(item[key], item[key])
        evidence = item['evidence']
        evidence = evidence.replace('No reliable observation.', 'Aucune observation fiable.')
        evidence = evidence.replace('Not observed in the completed check: ', 'Non observé lors du contrôle complet : ')
        evidence = evidence.replace('Observed: ', 'Observé : ')
        evidence = evidence.replace('Controlled origin tested; ACAO: ', 'Origine contrôlée testée ; ACAO : ')
        evidence = evidence.replace('; credentials header true: ', '; en-tête credentials vrai : ')
        evidence = evidence.replace(' Cookie count: ', ' Nombre de cookies : ')
        evidence = evidence.replace(' Method: ', ' Méthode : ').replace('; date: ', ' ; date : ')
        for key, english in CONDITIONS.items():
            evidence = evidence.replace(english, conditions[key])
        item['evidence'] = evidence
