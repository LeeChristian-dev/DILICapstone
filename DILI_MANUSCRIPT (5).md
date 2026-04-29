```
DILI: A BROWSER EXTENSION FOR DETECTING ILLEGAL LINK
```
INJECTIONS IN EDITED FACEBOOK LINKS AND MALICIOUS
REDIRECTS
An Information Technology Capstone Project
Presented to the Faculty of the College of Information and Computing
University of Southeastern Philippines
Bo. Obrero, Davao City
In Partial Fulfillment of the Requirements for the Degree of
BACHELOR OF SCIENCE IN INFORMATION TECHNOLOGY
Amor, Lee Christian P.
Epis, Regine L.
Mendez, Daphie Marie G.
Adviser
Tequin, Vera Kim.
December 2025
1
TABLE OF CONTENTS
TABLE OF CONTENTS................................................................................................ 2
CHAPTER I.................................................................................................................... 3
INTRODUCTION.......................................................................................................... 3
1.1 Background Of The Study.................................................................................. 3
1.2 Project Context....................................................................................................6
1.3 Objectives............................................................................................................8
1.4 Significance Of The Study.................................................................................. 9
1.5 Scope And Limitations......................................................................................10
CHAPTER 2..................................................................................................................11
REVIEW OF RELATED LITERATURE AND SYSTEMS.........................................11
2.1 Related Literature..............................................................................................11
2.2 Related Systems................................................................................................ 60
CHAPTER 3................................................................................................................. 65
FRAMEWORK AND METHODOLOGY................................................................... 65
3.1 Conceptual Framework..................................................................................... 65
3.2 Methodology..................................................................................................... 69
REFERENCES..............................................................................................................74
2
CHAPTER I
INTRODUCTION
1.1 Background Of The Study
```
The rapid expansion of Online Social Networks (OSNs) has transformed
```
digital communication, commerce, and information dissemination on a global scale.
As of the first quarter of 2025, Facebook reports approximately 3.07 billion monthly
active users worldwide, making it the largest social media platform in operation [1].
Social media platforms collectively account for billions of daily content interactions,
with users continuously generating and redistributing hyperlinks, multimedia, and
textual information across interconnected networks. However, this scale has also
produced a correspondingly large attack surface. Cybersecurity reports indicate that
social media platforms became the most targeted sector for phishing attacks in late
2023, accounting for approximately 42.8% of all phishing attempts in the fourth
quarter of that year, and remaining at 30.5% globally in the third quarter of 2024 [2],
[3]. These figures demonstrate that social media is no longer merely a communication
platform but a primary infrastructure exploited for large-scale malicious link
distribution.
Malicious hyperlink attacks represent one of the most prevalent technical
vectors within OSNs. According to Google Safe Browsing statistics, billions of unsafe
URLs are flagged annually, with phishing and malware-hosting sites frequently
propagated through social platforms [4]. Check Point Research further reported that
Facebook consistently ranks among the top brands impersonated in phishing
campaigns, accounting for approximately 18% of social-media-related brand phishing
```
incidents in 2023 [5]. These attacks are not limited to credential harvesting; modern
```
campaigns use redirect chains, cloaking techniques, URL obfuscation, and dynamic
content swapping to evade automated detection systems [6], [7]. Technically, these
methods exploit the temporal gap between initial link scanning and subsequent content
changes, allowing attackers to weaponize trusted posts after verification mechanisms
have completed their checks.
At the national level, the Philippines continues to experience high levels of
social media engagement, intensifying exposure to malicious links. As of 2024, the
Philippines recorded over 86 million active social media users, with Facebook serving
as the dominant platform [8]. Reports from the Philippine National Police
3
```
Anti-Cybercrime Group (PNP-ACG) and the Cybercrime Investigation and
```
```
Coordinating Center (CICC) show a consistent increase in phishing, online fraud, and
```
link-based scams, many of which originate from or circulate within Facebook posts
and Messenger communications [9]. In 2023 alone, thousands of complaints related to
online scams were recorded, with financial losses reaching hundreds of millions of
pesos, often involving deceptive hyperlinks embedded in posts advertising fake job
offers, investment schemes, or fraudulent e-commerce listings [9], [10]. These
national statistics illustrate that malicious link dissemination is not only a global
phenomenon but a persistent and measurable local threat affecting Filipino users.
Facebook’s core functionality significantly contributes to the velocity of
hyperlink dissemination. Industry data indicates that more than 70% of Facebook
users engage in content sharing behaviors, including reposting links, sharing external
articles, and redistributing multimedia posts that contain embedded URLs [11]. Meta
reports that billions of posts are shared daily across Facebook’s news feed, groups, and
pages, with a substantial proportion containing external hyperlinks directed to
third-party websites [1], [12]. The platform’s engagement-driven ranking algorithm
further amplifies highly interacted posts, increasing their visibility proportionally to
the number of likes, comments, and shares received [13]. Consequently, a single post
containing an external hyperlink can propagate exponentially through social networks,
reaching thousands or even millions of users within hours. This large-scale
dissemination mechanism magnifies the potential impact of any malicious link
embedded within trusted content.
A critical but underexamined vulnerability arises from Facebook’s post-editing
capability. According to platform documentation, users are allowed to modify post
captions, embedded hyperlinks, and associated content even after publication [14].
While this feature supports correction of errors and content updates, it introduces a
structural security weakness. Facebook’s automated link-scanning mechanisms
primarily evaluate URLs at the moment of initial posting using preview crawlers and
reputation checks [4], [14]. However, subsequent edits are not consistently subjected
to the same level of automated revalidation. This creates a measurable temporal blind
spot in which an originally benign hyperlink can be replaced with a malicious
destination after the post has accumulated engagement and social trust.
Academic research identifies this manipulation pattern as a “chameleon
attack,” wherein attackers intentionally post harmless content to gain credibility before
4
altering it to include malicious elements [15]. Real-world malware campaigns such as
NodeStealer and SYS01stealer have demonstrated this tactic by hijacking Facebook
accounts, posting legitimate-looking content, and later modifying embedded links to
distribute credential-stealing malware [16], [17]. In documented incidents, attackers
waited until posts received significant interaction before replacing URLs with
phishing or malware-hosting domains, thereby exploiting both algorithmic
amplification and user trust dynamics. Technically, this strategy leverages redirect
chains, shortened URLs, and conditional cloaking to evade blacklist-based detection
systems [6], [7], [18]. Because these manipulations occur after initial validation,
traditional antivirus tools and URL reputation databases detect the threat only at the
moment of click, not at the moment of alteration.
The financial and security consequences of such attacks are substantial. The
```
FBI Internet Crime Complaint Center (IC3) reported that business email compromise
```
and related phishing schemes resulted in global losses exceeding USD 55 billion
between 2013 and 2023, with many campaigns involving social media reconnaissance
and link-based deception [19]. In Southeast Asia, social media-driven e-commerce
scams and job recruitment fraud have similarly produced multi-million-dollar losses,
often initiated through manipulated Facebook links [10], [20]. These data points
confirm that malicious link injection is not theoretical but operationally exploited at
scale, with measurable economic and privacy impacts.
Despite the documented threat landscape, existing security solutions remain
predominantly reactive. Antivirus software, browser-integrated URL filters, and
malicious URL databases such as Google Safe Browsing, PhishTank, URLHaus, and
VirusTotal evaluate links against known threat signatures or behavioral heuristics at
the point of access [4], [21], [22], [23]. While these tools effectively block recognized
malicious domains, they do not monitor hyperlink integrity within dynamic social
media posts. They cannot detect whether a link inside a Facebook post has been
altered after publication, nor can they compare the original and modified versions of a
hyperlink over time. Furthermore, Facebook does not provide proactive user
notifications when substantive hyperlink edits occur in posts previously viewed or
shared by users [14]. This structural limitation leaves a significant gap between link
modification and threat detection.
The convergence of high user engagement, large-scale hyperlink
dissemination, editable post structures, and reactive detection models establishes a
5
clear research problem. There is currently no widely deployed user-level system
capable of continuously monitoring Facebook posts for post-publication link
alterations, reconstructing redirect paths, evaluating threat intelligence in real time,
and alerting users before navigation occurs. Addressing this gap requires a proactive,
browser-integrated solution capable of performing integrity verification, redirect
analysis, and threat scoring within the user’s browsing environment.
In response to this identified vulnerability, this study proposes the development
```
of DILI (Detecting Illegal Link Injections), a browser extension designed to detect
```
unauthorized hyperlink modifications and malicious redirect behaviors in edited
Facebook posts. By shifting from reactive blacklist-based defense to continuous
integrity monitoring and real-time risk evaluation, DILI aims to mitigate the temporal
blind spot inherent in Facebook’s post-editing architecture. This research therefore
contributes to the advancement of proactive, client-side security mechanisms
specifically tailored to dynamic social media environments.
1.2 Objectives
The primary objective of this study is to design and develop a proactive
browser-based extension that detects post-publication hyperlink alterations and
malicious redirect behaviors within Facebook posts. The system aims to address the
temporal security gap created by Facebook’s post-editing feature by implementing
continuous client-side monitoring instead of one-time link validation. Through
real-time integrity verification and redirect analysis, the study seeks to reduce user
exposure to phishing, malware distribution, and identity theft originating from edited
posts. The overall goal is to enhance user-level security within dynamic social media
environments.
Specifically, this study aims to develop a real-time hyperlink monitoring
mechanism that extracts and tracks URLs embedded in Facebook posts and detects
modifications after publication. It intends to implement a cryptographic hash-based
integrity verification process that compares original and updated hyperlink signatures
to identify unauthorized changes. The system will reconstruct redirect chains and
evaluate domain reputation, structural URL anomalies, and external threat intelligence
to compute a measurable risk score. Finally, the study aims to provide real-time alerts
6
and optional navigation blocking before user interaction, and to evaluate the system’s
detection accuracy, response time, and operational efficiency in controlled testing
scenarios.
1.3 Significance Of The Study
This study addresses a critical gap in social media security by developing a
proactive solution for post-publication link manipulation on Facebook. The
significance of this research lies in its contribution to user-level protection and the
advancement of client-side defense mechanisms within dynamic online social network
environments. Existing security infrastructures primarily perform link validation at the
point of posting or during access, leaving a temporal gap when posts are edited after
gaining engagement. By introducing continuous hyperlink monitoring, redirect
analysis, and structured threat evaluation, this study strengthens protective measures
against dynamic link-based attacks that occur after initial validation.
For Facebook users, the proposed system enhances protection against
malicious hyperlink alterations that occur after posts have accumulated likes,
comments, and shares. By implementing hyperlink integrity monitoring, redirect chain
reconstruction, URL validation, and real-time pre-click alert mechanisms, the system
reduces user exposure to phishing, malware distribution, fraud, and other forms of
cyber exploitation. The use of cryptographic hash comparison and measurable risk
scoring provides a structured and technology-driven method for identifying
unauthorized modifications. This directly supports the objective of fast, accurate, and
secure detection of malicious link edits before user interaction occurs.
For the social media and cybersecurity community, this research highlights
structural vulnerabilities in existing platform defenses, particularly Facebook’s
reactive link scanning model and dependence on user reporting mechanisms. The
study demonstrates how continuous client-side monitoring, redirect path analysis, and
threat intelligence integration can mitigate temporal attack vectors that current tools
fail to address. By formalizing a framework for detecting post-publication hyperlink
manipulation, it contributes a replicable and technically grounded approach to
securing editable online content. This supports the objective of providing structured
monitoring of link redirection and enabling timely user notification for potential
threats.
7
For developers and future researchers, this study provides a proof-of-concept
implementation of a browser-based extension designed to monitor dynamic social
media content. It illustrates how proactive, client-side security mechanisms can
complement platform-level protections and traditional antivirus systems. The system
architecture, including integrity verification, redirect analysis, and risk scoring
components, may be adapted to other platforms that support post editing and hyperlink
embedding. This directly fulfills the objective of demonstrating the feasibility of a
browser-based solution for detecting post-publication content manipulation.
1.4 Scope and Limitations
Scope
This study focuses on monitoring post-publication link alterations specifically
on Facebook, where the system detects unauthorized changes in hyperlinks after
content has been shared and validated through user engagement. The proposed
solution is implemented as a browser extension for Google Chrome, ensuring
compatibility and operational stability within a Chromium-based desktop
environment. It leverages client-side monitoring techniques to observe hyperlink
attributes and structural changes in real time, enabling the detection of modified URLs
and suspicious redirect behavior. The system provides immediate alerts to users once a
discrepancy in link integrity is identified.
Within Facebook, the system operates across key sections such as the
newsfeed, groups, pages, and marketplace, where hyperlink sharing commonly occurs.
The monitoring process focuses primarily on identifying link redirection patterns and
potential malicious modifications to embedded URLs after publication. It performs
integrity verification and redirect analysis before user navigation occurs, thereby
reducing exposure to phishing, malware, and fraudulent destinations. The extension is
designed to complement existing platform defenses and antivirus tools by providing an
additional client-side security layer rather than replacing current security
infrastructures. While Facebook is the primary platform under study, the underlying
8
monitoring concept may be adapted to other online social networks that allow
post-editing in future implementations.
Limitations
The system is limited to Facebook and does not extend support to other social
media platforms such as Instagram, Twitter/X, TikTok, or similar applications that also
allow post editing or link embedding. It is specifically designed to detect alterations to
hyperlinks and does not analyze changes to non-hyperlink components of posts,
including textual content, images, videos, or metadata. As a result, content
manipulation that does not involve URL modification is outside the detection
capability of the system. The extension focuses exclusively on hyperlink integrity and
redirect behavior.
The implementation is constrained to desktop environments and does not
support mobile browsers or Facebook’s mobile application. The system operates only
within Chromium-based browsers and is not compatible with non-Chromium
platforms such as Mozilla Firefox or Apple Safari due to architectural limitations of
the extension framework. Although the solution performs redirect tracing and risk
evaluation, it may not detect highly sophisticated or deeply obfuscated redirect
techniques employed by advanced threat actors. Furthermore, offline threats or attacks
occurring outside the browser environment fall beyond the operational scope of this
system.
CHAPTER 2
REVIEW OF RELATED LITERATURE AND SYSTEMS
2.1 Related Literature
9
```
2.1.1 ONLINE SOCIAL NETWORKS (OSNs) AND SECURITY RISKS
```
```
Online Social Networks (OSNs), such as Facebook, Instagram, and TikTok,
```
have fundamentally changed the way people interact and share content. These
platforms enable users to connect with others globally, exchange information, and
engage in various activities like business promotions, networking, and entertainment.
However, the immense scale of OSNs also introduces significant security risks,
particularly due to their interconnected nature and the volume of personal data being
```
exchanged. As Abomhara and Køien (2015) discussed, the security risks associated
```
with OSNs arise from a combination of system vulnerabilities, malicious threats, and
the potential consequences of attacks. Given the large-scale data flow across these
networks, even a small breach can have far-reaching effects, affecting millions of
users simultaneously [24].
The interconnected structure of OSNs amplifies the risks by allowing attackers
to exploit vulnerabilities that affect not only one individual but entire networks. The
platforms' reliance on user-generated content and their open nature make it difficult to
```
control the spread of malicious activities. According to Goga et al. (2017), malicious
```
actors can exploit user trust, which is a core aspect of OSNs, to rapidly disseminate
harmful content. The algorithms that rank content based on user engagement
inadvertently promote harmful posts, thereby amplifying their reach [25]. This creates
an environment in which malicious content can spread far and wide before being
detected, making OSNs highly vulnerable to security breaches.
2.1.1.1 TRUST AND SECURITY VULNERABILITIES
Trust is one of the cornerstones of OSNs, and it significantly shapes the way users
```
interact with the platform and the content shared within it. Goga et al. (2017) observed
```
that users tend to trust content shared by friends or people within their social circles,
which makes them more likely to click on links or engage with posts without verifying
their authenticity. This blind trust creates a significant security vulnerability. Malicious
actors often take advantage of this by embedding harmful links in posts that appear to
```
come from familiar and trusted sources (Goga et al., 2017) [25]. As a result, even the
```
most carefully crafted social engineering attacks can have a higher success rate on
OSNs than in other forms of online interactions.
```
Further research by De Cristofaro et al. (2016) has expanded on how OSNs leverage
```
user trust to enable the spread of malicious content. Users often do not question the
10
legitimacy of links shared by friends or acquaintances, which increases the likelihood
```
of them falling victim to phishing attacks. De Cristofaro et al. (2016) emphasized that
```
the social nature of these platforms facilitates the manipulation of trust, allowing
```
attackers to effectively infiltrate the network and disseminate malicious links (De
```
```
Cristofaro et al., 2016) [35]. The trust-based vulnerabilities are compounded by the
```
rapid dissemination of content due to the algorithms that prioritize popular posts,
making malicious links even more dangerous once they are shared within a social
circle.
2.1.2 MALICIOUS LINK ALTERATION IN OSNs
With the growing popularity of post-editing features on platforms like
```
Facebook, new security vulnerabilities have emerged. Elyashar et al. (2020)
```
introduced the concept of the "Chameleon Attack," where attackers change the links
within a post after it has gained significant user engagement. Initially safe links can be
substituted with malicious ones, taking advantage of the platform's lack of real-time
content validation mechanisms. The altered link may go unnoticed for an extended
period, even though the post has already gained considerable visibility and
```
engagement (Elyashar et al., 2020) [26]. This tactic is particularly insidious because
```
users assume that the content they engaged with previously remains unchanged, but in
reality, the link may now lead to a malicious site designed to steal personal data or
spread malware.
The issue is exacerbated by the nature of OSNs, where content often goes viral,
```
gaining widespread attention across users. Singh and Agarwal (2018) further
```
elaborated on how the design of OSNs contributes to the success of these types of
attacks. Most users do not revisit posts they have previously interacted with, which
creates a window of opportunity for attackers to alter the content of these posts
```
without detection. Singh and Agarwal (2018) pointed out that this vulnerability is
```
amplified by algorithms that promote content with high engagement, ensuring that
```
malicious posts are more likely to be amplified and shared widely (Singh & Agarwal,
```
```
2018) [27]. This creates a loop in which harmful content is continuously shared and
```
propagated, making it more difficult to stop before significant damage is done.
2.1.2.1 THE IMPACT OF ALGORITHMIC AMPLIFICATION
The amplification of posts by OSN algorithms plays a significant role in the
effectiveness of chameleon attacks. These algorithms are designed to prioritize content
11
that garners the most likes, comments, and shares, pushing popular posts to the top of
```
users' feeds. Elyashar et al. (2020) emphasized that this popularity-based amplification
```
means that once a post gains traction, any changes to the content, including the
substitution of safe links with malicious ones, are less likely to be noticed by users
```
(Elyashar et al., 2020) [26]. Therefore, malicious actors can exploit this feature to
```
spread harmful content across the platform more quickly, relying on the social
validation of popular posts to conceal their attack.
2.1.3 REDIRECTION AND PHISHING IN SOCIAL MEDIA
Phishing attacks, particularly those involving redirects, are one of the most
```
common threats on OSNs. Rafique and Humayun (2021) highlighted how attackers
```
use multi-step redirects to disguise the true destination of a link. These multi-step
chains often involve cloaking techniques that mask the final destination, making it
difficult for users to identify the malicious intent behind the link. Rafique and
```
Humayun (2021) noted that these types of attacks are particularly effective on
```
platforms like Facebook, where users are constantly engaging with content that could
```
be altered post-publication to lead to a phishing site (Rafique & Humayun, 2021) [28].
```
2.1.3.1 CHALLENGES IN REDIRECT DETECTION
```
Gupta et al. (2020) discussed how traditional security systems are often
```
inadequate at detecting multi-step redirects, especially in OSNs. These systems are
typically designed to monitor links only when they are first posted or accessed, which
means they fail to detect when malicious redirects are embedded into posts after
publication. This leaves users vulnerable to attacks that occur after the link has already
been validated, making it more difficult to identify and stop phishing attacks once they
```
have been initiated (Gupta et al., 2020) [29]. As social media platforms continuously
```
evolve, the ability of these systems to adapt and detect new attack vectors becomes
increasingly important.
2.1.4 EXISTING SECURITY MECHANISMS ON FACEBOOK
Facebook has implemented several security mechanisms, such as link scanners
and the "Report Post" feature, to combat malicious content. However, these measures
are largely reactive, only addressing security threats after they have been reported by
```
users or detected by the system. Elyashar et al. (2020) pointed out that this reactive
```
12
approach is ineffective against chameleon attacks, where links are altered after the
post has already gained significant visibility. Once a post is published, Facebook's
security protocols do not continuously monitor or validate the content, which allows
```
attackers to manipulate the links without triggering any security alerts (Elyashar et al.,
```
```
2020) [26].
```
2.1.5 SOCIAL MEDIA SECURITY
Social media platforms are among the most widely used communication
systems in the modern digital environment, enabling users to share content,
communicate instantly, and participate in online communities. The scale and openness
of these platforms make them valuable for information exchange, but they also create
persistent cybersecurity risks because adversaries can reach large audiences with
minimal effort. Widespread adoption increases the attack surface, and the volume of
daily user-generated content makes real-time monitoring difficult even with automated
moderation pipelines [11], [30]. As a result, social media platforms have become
attractive targets for cybercriminals who exploit user trust and platform mechanisms to
distribute malicious links, phishing pages, and other harmful content [30].
Security challenges in OSNs are often campaign-driven rather than isolated
events, because attackers can coordinate accounts, reuse infrastructure, and rapidly test
variations until defenses are bypassed. Prior studies note that malware and scam
content can propagate through network connectivity and repeated sharing, making the
spread pattern itself part of the threat [25], [40]. At the same time, many attacks
depend on persuasion rather than purely technical exploitation, since users may click,
share, or submit information when a post appears socially relevant or personally
credible [35]. These conditions require OSN security strategies that combine
automated link analysis, behavioral monitoring, and scalable response mechanisms
[25], [30].
Another major concern is the speed at which malicious content can spread due
to engagement-based ranking and recommendation. Algorithmic amplification
increases the visibility of content that receives strong interaction signals, which can
unintentionally accelerate the distribution of harmful links when attackers craft posts
that generate clicks and shares [13]. Because a malicious link can become widely
exposed before manual review or user reports take effect, relying only on reactive
moderation is often insufficient [30]. Research on malicious website detection also
suggests that blacklist-only approaches struggle when attackers rapidly generate new
13
domains and URLs, especially during the early stages of a campaign [34].
Consequently, OSN security benefits from proactive detection systems that can
identify suspicious link behavior early and limit dissemination before large-scale
exposure occurs [13], [34].
2.1.5.1 Trust-Based Vulnerabilities in Social Networks
Trust strongly influences how users evaluate social media content, particularly
when deciding whether to click on a link shared by a friend, follower, or familiar page.
In OSNs, social relationships can unintentionally function as credibility signals,
reducing skepticism even when the destination is risky [25]. This creates an
opportunity for attackers, since compromising one account or impersonating a trusted
identity can immediately increase the success rate of malicious link distribution. The
problem is intensified by the fact that spam and abuse infrastructure can be produced
and rotated at scale, allowing attackers to maintain campaigns even when some
domains are removed or blocked [31].
Trust-based vulnerabilities become more severe when malicious content
spreads through social sharing chains. Once a harmful link is introduced into a group,
it may propagate quickly as users repost, forward, or comment, creating a cascade that
amplifies exposure [25]. Social engineering further strengthens this effect by
exploiting psychological triggers such as urgency, fear, or rewards, which can override
careful verification and encourage immediate interaction [35]. Large-scale analyses of
malware in social networks also show that attackers benefit from network structure
and user interactions that naturally support diffusion [40]. These findings suggest that
OSN defenses should not only evaluate a URL’s characteristics, but also consider the
trust context and sharing behavior that can signal coordinated abuse or account
compromise [25], [40].
2.1.5.2 Algorithmic Amplification and Rapid Threat Diffusion
Recommendation systems and ranking algorithms are designed to maximize
engagement, but they can also accelerate the spread of harmful content when a
malicious post is framed in a highly engaging way. Content that triggers strong
reactions such as sensational news, urgent warnings, or emotionally charged narratives
may receive increased distribution through platform mechanisms [13]. When
malicious links are embedded into such content, amplification can quickly turn a
small-scale attack into a wide-reaching exposure event. This creates a time-critical
14
security problem, because delayed detection can allow a link to reach large audiences
before intervention [30].
Rapid diffusion also pressures detection systems to operate in real time and at high
throughput. As campaigns evolve, attackers can modify domains, rotate URLs, and
adjust message templates to bypass filters, which reduces the effectiveness of static or
purely signature-based defenses [34]. Real-time filtering services demonstrate that link
analysis pipelines can be effective when they incorporate continuous updates, scalable
classification, and automated enforcement [38]. However, OSN-specific conditions
like post edits, re-shares, and cross-platform reposting require monitoring beyond
initial posting time. For this reason, the literature supports detection designs that
combine early-stage automated checks with continuous observation of link behavior as
content spreads [13], [38].
2.1.6 MALICIOUS LINK MANIPULATION
Malicious link manipulation refers to altering or crafting URLs in ways that
```
deceive users into visiting harmful destinations. Garera et al. (2007) explain that
```
attackers design links that appear legitimate but include subtle cues such as misleading
subdomains, suspicious parameters, or encoded characters that conceal the real target
[32]. This manipulation is effective because many users rely on quick visual
inspection and may not notice small differences in spelling, domain structure, or URL
```
hierarchy. Ma et al. (2009) further show that relying on known lists of malicious sites
```
is often insufficient because adversaries can produce new domains and URL variants
quickly, especially during active campaigns [34]. As a result, manipulated URLs
remain a major delivery channel for phishing pages, malware downloads, and online
fraud across social platforms [32], [34].
In social media environments, malicious link manipulation becomes more
dangerous because posts can persist and remain discoverable long after publication.
```
Lin et al. (2022) discuss that engagement-based distribution can keep highly
```
interactive posts circulating, meaning a manipulated link embedded in popular content
```
can continue receiving clicks over time [13]. Bursztein et al. (2017) emphasize that the
```
scale and velocity of OSN content makes it difficult to detect and remove harmful
links quickly, particularly when attackers repeatedly test variants to bypass filters [30].
```
In addition, Zhang et al. (2007) highlight that anti-phishing tools vary in effectiveness,
```
15
and attackers exploit these gaps by adjusting link patterns and delivery strategies to
avoid detection [37]. These conditions support the need for defenses that evaluate
URL structure and also monitor how shared links evolve after posting, which is central
to DILI’s concern with illegal link injections [15].
2.1.6.1 URL Obfuscation Techniques
URL obfuscation is used to disguise malicious links so they appear safe or
```
familiar to users. Garera et al. (2007) note that attackers frequently manipulate visible
```
URL elements to reduce suspicion, including adding misleading tokens, using
confusing directory paths, or crafting long strings that bury the meaningful parts of the
```
URL [32]. Provos et al. (2008) further show that web-based attacks often rely on
```
deceptive delivery mechanisms, which makes the true destination harder to interpret
without automated analysis [33]. Attackers also use shortening services and
redirection layers so the displayed URL does not reveal the final landing page,
increasing click-through likelihood and reducing user verification [29]. These tactics
are effective because normal web conventions already allow complex URL structures,
making malicious obfuscation blend into everyday browsing [33], [34].
Obfuscation also weakens blacklist-based defenses because each link can be
made to look unique even when the underlying campaign infrastructure is related. Ma
```
et al. (2009) demonstrate that detection systems perform better when they go beyond
```
simple blocklists by learning patterns from lexical and host-based features, allowing
```
them to generalize to unseen malicious URLs [34]. Antonakakis et al. (2012)
```
additionally highlight that abuse ecosystems are supported by domain registration
behavior that enables rapid creation and rotation of domains, which attackers use to
```
maintain continuity even when some domains are blocked [31]. Sahoo et al. (2017)
```
discuss that machine learning-based approaches can combine lexical, network, and
host signals to improve detection accuracy under adversarial variation [6]. Therefore,
robust URL defenses typically integrate multiple feature classes and do not rely on
URL appearance alone [6], [34].
2.1.6.2 Post-Publication Link Substitution and “Chameleon” Behavior
Post-publication link substitution occurs when a link is changed after a post
```
has already gained visibility, engagement, and trust from users. Elyashar et al. (2020)
```
describe this “chameleon” behavior, showing that attackers can initially share benign
content to attract likes, shares, and comments, then later replace the link destination
16
with a malicious URL once the post has become widely distributed [15]. This tactic is
especially harmful in OSNs because the trust-building phase happens before the
malicious destination is introduced, and many users encounter the post later through
```
reshares or recommendations without noticing edits. Lin et al. (2022) help explain
```
why this matters: engagement-based ranking can keep popular posts circulating,
allowing a substituted link to continue receiving exposure long after the change occurs
[13]. In effect, post-edit manipulation converts a previously trusted post into a delivery
vehicle for phishing or malware while maintaining the credibility built during earlier
interactions [15].
This manipulation pattern reduces the effectiveness of one-time scanning
approaches that evaluate links only at the moment of posting or first click. Ma et al.
```
(2009) show that malicious sites can emerge and evolve quickly, meaning even a link
```
that was safe earlier may later redirect to harmful infrastructure that was not
```
previously detected [34]. Provos et al. (2008) demonstrate that attackers often rely on
```
layered delivery tactics and compromised resources, which can conceal malicious
behavior until conditions are favorable, making static inspection unreliable [33].
```
Gupta et al. (2020) also emphasize that redirect behavior is a key evasion method in
```
social-media link attacks, since adversaries can change intermediate hops or final
destinations without changing how the initial link looks to users [29]. These findings
justify integrity-focused monitoring where platforms compare current destination and
redirect behavior against earlier known-good states, aligning directly with DILI’s goal
of detecting illegal link injections after publication [15], [29].
Attackers may strengthen substitution attacks by combining them with URL
shorteners, tracking links, or multi-step redirection so that the change is not obvious in
```
the visible post. Thomas et al. (2011) describe how real-time URL filtering services
```
must handle high volume and evolving spam infrastructure, which resembles OSN
```
conditions where link targets can shift rapidly [38]. Stallings (2017) provides the
```
foundational integrity concept that cryptographic fingerprints can detect unauthorized
alterations by comparing current content against stored reference values [36]. While
cryptographic integrity alone may not capture every benign edit scenario, it becomes
more practical when paired with behavioral indicators such as abrupt domain changes,
suspicious redirect chain growth, or sudden spikes in resharing activity [29], [38].
Thus, the literature supports continuous, post-publication monitoring as a necessary
complement to click-time defenses for protecting OSN users from illegal link
injections [15], [36].
17
2.1.7 PHISHING LINKS
Phishing attacks remain one of the most common cybersecurity threats faced
by internet users because they exploit both technical weaknesses and predictable
```
human behavior. The Anti-Phishing Working Group (APWG, 2024) reports that
```
phishing activity continues to rise and that attackers consistently adapt their methods
to bypass security controls and increase success rates [2]. In online social networks,
phishing is especially effective because links can be distributed rapidly through posts,
comments, group pages, and direct messages, allowing campaigns to reach many
```
potential victims in a short period of time [25], [30]. Ma et al. (2009) also show that
```
defenders cannot rely only on blacklists, since phishing sites and malicious domains
can appear and disappear quickly, leaving a detection gap during the most active stage
of an attack [34]. These conditions explain why phishing links remain persistent across
social platforms even when platforms deploy automated moderation and URL filtering
[30], [34].
Phishing websites are typically designed to impersonate legitimate services
such as banks, email providers, e-commerce platforms, or social media login pages.
```
Garera et al. (2007) describe that phishing campaigns often rely on deceptive link
```
delivery and imitation of trusted brands to trick users into submitting credentials or
personal data [32]. Once victims enter information into a fake page, attackers can
capture it immediately and reuse it for account takeover, identity fraud, or further
```
social engineering. Zhang et al. (2007) further highlight that anti-phishing tools have
```
uneven effectiveness across different phishing designs and delivery strategies,
allowing some campaigns to evade defenses long enough to collect victims’
credentials [37]. As a result, phishing links continue to be dangerous in OSNs because
they combine visual deception, rapid distribution, and high user trust in familiar
platforms [32], [37].
Phishing link delivery also benefits from the social context and platform
```
engagement patterns that shape user behavior. Hadnagy (2011) explains that social
```
engineering works by leveraging psychological triggers such as urgency, fear,
curiosity, and reward framing, which reduces careful verification and increases
impulsive clicking [35]. In OSNs, attackers can craft messages that appear to come
from a friend, a verified page, or a community group, which increases credibility and
```
lowers suspicion [25]. Bilge et al. (2009) show that large-scale malware and abuse
```
18
campaigns in social networks often exploit the network structure itself to maximize
reach, and the same diffusion effects can support phishing link spread [40]. Therefore,
phishing links in OSNs must be analyzed not only as suspicious URLs but as part of
broader campaigns that combine manipulation of attention, trust, and sharing
mechanisms [35], [40].
2.1.7.1 Social Engineering in Phishing Attacks
Social engineering is a critical component of phishing because it targets the
```
human decision process rather than only technical vulnerabilities. Hadnagy (2011)
```
```
emphasizes that attackers frequently use persuasion techniques such as urgency (“act
```
```
now”), authority (“official notice”), scarcity (“limited time”), or rewards (“you won”)
```
to push victims toward immediate action [35]. These tactics are effective on social
media where users often scroll quickly, make rapid judgments, and react emotionally
```
to content rather than verifying URLs carefully. APWG (2024) reports that phishing
```
campaigns routinely use convincing pretexts and impersonation strategies, reinforcing
the idea that deception is central to phishing success even when technical defenses
exist [2]. As a result, user susceptibility is strongly influenced by message framing,
perceived legitimacy, and social context rather than by the URL alone [35].
Social media environments amplify social engineering because malicious posts
can be reshared and reinforced by social proof. When users see content that appears
popular—many likes, comments, or shares they may assume it is safe, which reduces
```
skepticism and increases click-through probability [13], [25]. Lin et al. (2022) show
```
that algorithmic amplification increases the visibility of highly engaging posts, and
attackers can exploit this by crafting emotionally compelling phishing narratives that
```
generate rapid interaction [13]. In addition, Bilge et al. (2009) demonstrate that abuse
```
in social networks can scale quickly when content propagation follows normal social
diffusion patterns, meaning phishing messages can spread naturally once they enter a
community [40]. These findings support the need for security systems that detect
suspicious link behavior early, monitor propagation patterns, and intervene before
social proof and recommendation systems amplify the attack [13], [40].
2.1.7.2 Phishing Website Characteristics and Visual Deception
A major reason phishing succeeds is that fake websites are designed to closely
mimic legitimate services, including logos, typography, layouts, and authentication
```
prompts. Garera et al. (2007) explain that phishing pages often replicate visual
```
19
elements of trusted brands to create a sense of authenticity and reduce user doubt [32].
Victims commonly focus on the page appearance instead of validating the domain
name, certificate details, or URL path, which enables attackers to steal credentials
```
even when users believe they are on an official site. Zhang et al. (2007) show that
```
some anti-phishing tools fail when deception relies on visual similarity and novel
domain infrastructure, because the site may not yet be flagged or may avoid heuristic
triggers [37]. Consequently, visual imitation remains a persistent strategy that
complements link manipulation and increases campaign effectiveness [32], [37].
Phishing sites also frequently use technical tricks to increase credibility, such
as HTTPS certificates, realistic subdomains, and login flows that resemble genuine
```
“single sign-on” prompts. Antonakakis et al. (2012) note that attackers can efficiently
```
build and rotate domain infrastructure, which supports fast deployment of phishing
pages that look legitimate but exist only briefly to avoid takedowns [31]. Ma et al.
```
(2009) reinforce that detection must learn patterns rather than depend only on known
```
malicious domains, because many phishing sites are new and short-lived at the time
victims encounter them [34]. These observations indicate that phishing defenses need
multi-signal evaluation: URL features, hosting behavior, redirect patterns, and
contextual indicators such as sudden sharing spikes or edits that change link
destinations [34], [40]. For OSNs, this supports DILI-aligned monitoring where the
platform evaluates not just whether a URL is suspicious, but whether its behavior and
lifecycle suggest coordinated deception or illegal link injection [15], [34].
2.1.8 REDIRECT ATTACKS
Redirect attacks occur when a user clicks a link that appears legitimate but is
automatically sent to a different destination without clear notice. Rafique and
```
Humayun (2021) describe redirect-based phishing as a technique that hides the final
```
malicious landing page behind intermediate steps, making detection harder for both
users and some security tools [7]. In many cases, attackers use redirection to disguise
malicious infrastructure, rotate destinations quickly, or bypass filtering that only
```
checks the initial URL. Gupta et al. (2020) note that these attacks are common in
```
social media because external links and shortened URLs are widely shared, and users
often trust links posted by friends or familiar pages [29]. As a result, redirect attacks
can deliver users to phishing sites, malware downloads, or fraudulent services even
when the original shared link looks safe [7], [29].
20
A key difficulty in handling redirect attacks is that the threat may not be visible
```
from the starting URL alone. Provos et al. (2008) show that web-based attacks often
```
use intermediate resources and layered delivery mechanisms to conceal malicious
behavior, which aligns with how redirect chains can hide the true endpoint from
```
simple inspection [33]. Ma et al. (2009) also emphasize that blacklist-only defenses
```
struggle when attackers frequently change destinations or use new malicious domains,
since the final landing page may not be known at the moment a user clicks [34]. In
OSNs, this risk increases because content spreads quickly and users may click links
repeatedly as posts resurface through sharing and engagement-driven ranking [13].
Therefore, redirect attacks highlight the need for detection systems that evaluate link
behavior dynamically rather than relying solely on static checks of the initial URL
[29], [34].
Multi-step redirection is particularly effective for evasion because each hop
can be used to obscure intent, alter tracking parameters, or perform conditional routing
```
based on the visitor. Gupta et al. (2020) explain that redirect chains may involve
```
legitimate services, compromised websites, or temporary “throwaway” pages, which
makes it harder to classify each step as malicious using simple rules [29]. Thomas et
```
al. (2011) similarly show that real-time URL spam filtering must process high
```
volumes of links and handle fast-changing infrastructure, reinforcing that practical
detection must be scalable and able to adapt quickly [38]. In practice, redirect-based
attacks can also change over time, where a previously benign redirect chain later starts
routing to a harmful destination after a campaign begins. This is closely connected to
post-publication risk in OSNs, where link behavior can drift and become malicious
after trust has already been established [15], [29].
Redirect attacks remain a major concern because they reduce transparency for
users and weaken the effectiveness of simple URL-based judgments. Many users do
not have visibility into where a redirect chain ends, and they may assume the
destination is safe if the initial link appears familiar or comes from a trusted account
```
[25]. Hadnagy (2011) explains that social engineering increases the success of such
```
attacks by encouraging rapid action and reducing verification, which makes redirect
deception even more effective in social feeds [35]. Because redirect attacks can be
both technical and psychological, effective mitigation typically requires layered
defenses that combine URL feature analysis, redirect chain evaluation, reputation
signals, and monitoring for suspicious changes in link behavior over time [6], [29]. In
OSN settings, this supports continuous monitoring approaches that can detect
21
unexpected redirect changes as potential indicators of illegal link injection or
campaign activation [15], [38].
2.1.9 URL DETECTION TECHNIQUES
Detecting malicious URLs is a core requirement in modern cybersecurity
because URLs are widely used to deliver phishing pages, malware downloads, and
```
fraudulent services. Sahoo, Liu, and Hoi (2017) explain that machine learning-based
```
URL detection has become popular because it can learn patterns from large datasets
and identify suspicious links even when they are not yet listed in blacklists [6]. This is
important in fast-moving threat environments where adversaries can register new
domains and generate fresh URL variants quickly, leaving a window of exposure
before reputation systems catch up [34]. In social media contexts, the challenge
becomes more severe because links spread rapidly and attackers can test many
versions until one bypasses filters, which increases the need for automated,
high-throughput detection [30], [38]. As a result, URL detection techniques are
typically designed to balance accuracy, speed, and robustness against evasive
manipulation [6], [34].
Traditional blacklist-based approaches remain useful, but they are limited by
```
coverage and time lag. Ma et al. (2009) show that blacklist-only methods struggle
```
against newly created malicious websites, since the infrastructure can be active long
```
before it is reported and added to blocklists [34]. Zhang et al. (2007) similarly
```
highlight that anti-phishing tools vary in effectiveness, which attackers exploit by
rotating domains and adjusting URL patterns to remain undetected [37]. In OSNs,
these gaps are amplified because recommendation and resharing can increase exposure
quickly, meaning detection delays translate into higher victim counts [13]. Therefore,
the literature supports hybrid strategies that combine reputation systems with
feature-based classification so that detection remains effective even under rapid
domain churn and zero-day campaigns [6], [34].
Machine learning approaches are often categorized by the type of signals they
use, including lexical URL features, host-based features, and behavioral features.
```
Sahoo et al. (2017) note that lexical features are attractive because they can be
```
extracted directly from the URL string without visiting the website, which reduces
computation cost and avoids exposing scanners to malicious payloads [6]. However,
attackers can manipulate lexical patterns through obfuscation, shortening, and
randomized tokens, which means lexical-only models may be less stable under
22
adversarial pressure [32], [33]. Host-based features such as domain age, WHOIS
```
patterns, and hosting behavior can add robustness, and Antonakakis et al. (2012) show
```
that abuse ecosystems often reveal detectable patterns in domain registration and
operational behavior that support large-scale spam and malicious campaigns [31]. In
practice, combining multiple feature classes generally improves resilience because it
reduces dependence on any single easily manipulated signal [6], [31].
2.1.9.1 Feature-Based URL Analysis
Feature-based URL analysis examines measurable attributes of a URL and its
```
associated infrastructure to estimate whether it is malicious. Ma et al. (2009)
```
demonstrate that learning-based detection can outperform simple blacklist checks by
modeling patterns that distinguish malicious sites from benign ones, even when the
malicious sites are previously unseen [34]. Common lexical indicators include
unusually long URLs, excessive use of special characters, suspicious tokens, and
domain structures that mimic trusted brands [6], [32]. Network and host indicators can
include domain age, registrar reputation, DNS volatility, and hosting anomalies, which
help capture characteristics of fast-flux or short-lived malicious infrastructure [31],
[34]. These features are particularly relevant in OSNs where attackers continuously
alter URL strings to evade static filters while keeping the underlying campaign
infrastructure consistent [30], [38].
Behavioral features strengthen feature-based analysis by focusing on what a
```
link does rather than how it looks. Gupta et al. (2020) emphasize that redirect behavior
```
is a key signal in social-media link threats because attackers frequently hide malicious
destinations behind multiple hops or change redirect chains over time [29]. Provos et
```
al. (2008) show that layered delivery mechanisms and web-based attack infrastructure
```
can conceal harmful behavior until the user reaches the final landing page, making
behavior-aware detection more reliable than static inspection alone [33]. Thomas et al.
```
(2011) also illustrate that real-time filtering systems benefit from scalable pipelines
```
that can evaluate URLs quickly while incorporating signals that adapt as campaigns
evolve [38]. Taken together, the literature indicates that effective malicious URL
detection in OSNs requires feature-based methods that integrate lexical, host, and
behavioral signals to remain accurate under rapid change and adversarial evasion [6],
[29], [34].
2.1.10 LINK VERIFICATION AND INTEGRITY CHECKING
23
Link verification mechanisms are used to ensure that web links remain
unchanged after they have been published, which is especially important in
environments where content can be edited, reposted, or repurposed over time.
```
Stallings (2017) explains that cryptographic techniques such as hashing can generate a
```
unique fingerprint for data, allowing systems to detect whether content has been
altered by comparing current values to stored reference values [36]. When applied to
URLs or post content, this concept supports integrity checking because even small
modifications such as changing a domain, adding a redirect parameter, or swapping a
shortened-link destination can be detected as a difference from the original reference
[36]. In OSNs, this capability matters because users often assume that a link in a
previously trusted post still points to the same destination, even though post-editing
features may allow the link to change later [15]. Therefore, integrity checking
provides a practical way to treat link changes as security-relevant events rather than
normal content updates, which supports the detection objectives of systems like DILI
[15], [36].
Integrity checking is also relevant because many link-based attacks rely on
```
timing and delayed activation. Elyashar et al. (2020) describe chameleon-style
```
manipulation where benign content is initially published to build engagement and
credibility, and only later is the link modified into a malicious destination [15]. In such
cases, one-time scanning at posting time may classify the original link as safe, while
the harmful behavior appears after trust has already been established. Snoeren et al.
```
(2012) discuss integrity-oriented approaches for web applications that detect
```
unauthorized modifications by tracking content fingerprints and comparing them
across time, which aligns with the idea of treating link changes as potential
compromise indicators [42]. This literature supports continuous or event-triggered
verification such as revalidating a link when a post is edited or when its redirect
behavior changes rather than relying only on initial classification [15], [42].
A practical challenge is distinguishing between legitimate edits and malicious
substitutions, since not all link changes are attacks. Some users may update links to
correct typographical errors, replace expired resources, or redirect followers to
updated pages, which are benign reasons for modification. However, Gupta et al.
```
(2020) highlight that attackers can exploit redirect mechanisms and multi-hop chains
```
to conceal changes in the final destination, meaning a link may look similar while the
```
endpoint becomes harmful [29]. Thomas et al. (2011) show that large-scale real-time
```
URL filtering systems can incorporate behavioral signals to identify suspicious
24
changes and prioritize enforcement actions under high volume [38]. For OSNs,
combining integrity checks with contextual indicators such as abnormal sharing
spikes, unusual edit timing, or sudden domain reputation changes improves practical
accuracy while minimizing false positives [29], [38].
Link verification can also be strengthened when paired with broader URL
```
evaluation and reputation modeling. Ma et al. (2009) demonstrate that learning-based
```
malicious website detection can generalize beyond known blacklists, which can help
determine whether a newly modified link now points to suspicious infrastructure [34].
```
Antonakakis et al. (2012) further show that abuse campaigns often rely on domain
```
registration behaviors that may be detectable through infrastructure signals, supporting
the use of domain-level context in verification decisions [31]. From a system design
viewpoint, integrity checking becomes most effective when it is integrated into a
workflow that includes automated re-scanning, redirect chain evaluation, and
platform-level monitoring of edits and propagation. In this sense, integrity checking is
not only a cryptographic concept but also an operational control that helps platforms
detect illegal link injection attempts before they reach large audiences [15], [34].
2.1.11 BROWSER AND SECURITY DETECTION SYSTEMS
Modern web browsers act as the first line of defense against malicious links,
drive-by downloads, phishing pages, and redirect-based attacks. Major browsers such
as Google Chrome, Mozilla Firefox, and Microsoft Edge deploy multiple layers of
protection, including URL reputation checks, permission prompts, anti-phishing
interstitial warnings, and process isolation to reduce the damage caused by
compromised web content. In practice, browser security is designed to operate at
scale, because users encounter untrusted links daily through social media feeds,
messages, and embedded advertisements. As a result, browser vendors continuously
update threat intelligence and enforce security policies that attempt to block known
malicious destinations before the page is fully loaded [4], [47].
Despite these defenses, browser protections are not always sufficient in online
```
social networks (OSNs), particularly when attackers exploit platform features such as
```
post editing and link rewriting. Many browser systems make decisions at click-time,
meaning the evaluation happens when the user navigates to the link, not when the link
is created, shared, or later modified. If a benign-looking link later becomes malicious
through post-publication substitution, shortened-link repointing, or multi-hop
25
redirects, the browser may not provide a strong guarantee that the originally trusted
content remains safe. This limitation motivates security models that incorporate
continuous link integrity checking and server-side monitoring, which aligns closely
with DILI’s objective of detecting illegal link injections at the platform level [7], [15].
2.1.11.1 Security Plugins and Extensions
Browser extensions and security plugins provide an additional security layer
by inspecting URLs and page behavior before or during navigation. Many extensions
apply heuristics such as lexical analysis of URLs, suspicious token detection,
certificate checks, and reputation scoring from external services. When combined with
lightweight machine learning models, these tools can warn users in real time,
especially in scenarios where a threat is too new to appear in traditional blacklists [6],
[34]. This capability is important for OSN-based attacks, because malicious links are
frequently generated in high volume and spread rapidly through sharing mechanisms.
However, extensions also face important constraints that limit their reliability
as a complete solution. Extensions typically operate within a restricted permission
model and rely on browser APIs, which can reduce their visibility into full redirect
chains or embedded third-party content. In addition, user adoption is inconsistent,
meaning that extension-based defenses cannot be assumed across the entire OSN user
base. Researchers also note that attackers increasingly design content to evade
client-side detection by delaying malicious redirects, using cloaking techniques, or
tailoring payloads based on user agent and location [33], [48]. These limitations
support the argument that OSN-level systems like DILI must complement
browser-side defenses by monitoring integrity and link behavior continuously.
2.1.11.2 Sandboxing, Site Isolation, and Execution Containment
Sandboxing and process isolation are core browser security mechanisms that
reduce the impact of malicious web pages by restricting what code can access. In
Chromium-based browsers, site isolation and multi-process architecture aim to prevent
one compromised page from reading data from another origin, which reduces the
chance of credential theft via cross-site data leakage. These mechanisms are
particularly valuable in drive-by infection scenarios, where simply visiting a malicious
page can trigger exploit attempts. From a threat modeling perspective, containment
26
reduces severity, but it does not prevent the user from being deceived into submitting
credentials or approving permissions on a phishing site [47], [49].
Containment also does not address the “link integrity” problem that arises
when users trust a post based on its initial content. Even if the browser safely isolates
execution, the user can still be redirected to a convincing phishing page and
voluntarily provide sensitive information. In OSNs, attackers often exploit
attention-based engagement mechanics by letting benign links go viral before
changing their destinations, which shifts the attack point from exploitation to
deception. Therefore, browser containment must be paired with detection systems that
focus on the evolution of shared links over time, including post-edit events, redirect
changes, and domain reputation drift features emphasized by DILI-style monitoring
[15], [29].
2.1.11.3 URL Reputation Services and Safe Browsing-Style Blocklists
Many browsers rely on URL reputation systems that aggregate telemetry,
community reports, and threat intelligence feeds to warn users about phishing and
malware destinations. For example, Safe Browsing-style approaches maintain lists of
suspected malicious URLs and provide warnings before navigation. These
mechanisms are effective against known threats and large phishing campaigns,
because they can block repeated infrastructure reuse at scale [4], [34]. They also
reduce the burden on users by providing clear UI warnings rather than requiring
manual URL inspection.
At the same time, reputation-based systems have a known “coverage gap”
against zero-day malicious domains, short-lived hosting, and rapidly rotated redirect
infrastructure. Attackers often use URL shorteners, compromised sites, or disposable
domains to stay ahead of blocklists, which can delay detection during the early spread
of a campaign. In OSNs, this delay is costly because harmful links can reach large
audiences within minutes. Consequently, literature supports hybrid approaches that
combine reputation feeds with feature-based classification and behavioral analysis of
redirects, enabling earlier detection of suspicious link manipulation [6], [38], [50].
2.1.12 REAL-TIME URL VERIFICATION AND INTEGRITY MONITORING
27
Real-time link verification focuses on ensuring that a previously published
URL or embedded link remains unchanged and points to the same intended
destination. Integrity monitoring can be implemented through cryptographic
fingerprints, trusted logging, and continual revalidation of link destinations. This is
particularly relevant in OSNs where post-publication editing is common, and attackers
can attempt to substitute malicious destinations after trust has been established [15],
[32]. In such settings, integrity monitoring shifts detection from “first click” to
“lifecycle protection,” where the system watches how links evolve over time.
From a systems perspective, real-time verification is challenging because it
must handle high volumes of posts, shortened URLs, redirects, and content changes
while keeping latency low. The literature shows that combining link structure analysis,
redirect chain resolution, and domain reputation can reduce exposure to phishing and
malware before harm occurs [30], [38]. Real-time verification also benefits from
event-driven triggers, such as re-checking a link when a post is edited or when a
destination begins redirecting differently than before. These design principles connect
directly to DILI’s role in detecting illegal link injections by comparing current link
states to trusted baselines.
2.1.12.1 Detection of Multi-Step Redirects
Multi-step redirect chains are widely used to hide malicious landing pages
behind several intermediate hops. Each hop can be hosted on a different server,
sometimes mixing legitimate services with compromised infrastructure, making
detection more difficult when only the initial URL is inspected. Studies emphasize that
attackers use redirects to evade both user inspection and automated scanners by
delaying the final malicious landing page or returning benign content to certain
crawlers [29], [33]. As a result, advanced detection systems attempt to expand and
analyze the entire redirect chain, including HTTP status transitions, JavaScript-based
redirects, and meta-refresh behavior [33], [38].
Real-time redirect analysis is especially important for social media
environments because shortened URLs and tracking links are common, and users are
less likely to evaluate link destinations carefully. Traditional blacklist methods often
fail when intermediate hops are not previously known as malicious, even if the final
landing page is harmful. Machine learning approaches can address this by modeling
28
redirect features such as chain length, domain diversity, time-to-final landing, and
suspicious parameter patterns that correlate with phishing infrastructure [6], [50].
Therefore, DILI-type monitoring can treat redirect-chain shifts as integrity violations,
flagging posts whose destination behavior changes unexpectedly.
2.1.12.2 Cryptographic Integrity Approaches and Web Standards
Cryptographic techniques such as hashing and digital signatures provide a
concrete method to detect whether content has changed since publication. In general,
hashing creates a compact fingerprint that changes when the underlying data changes,
enabling verification of integrity and tamper detection in distributed systems [36]. In
the web ecosystem, integrity concepts are also reflected in standards such as
```
Subresource Integrity (SRI), which allows browsers to verify that externally loaded
```
resources match expected hashes, reducing the risk of silent third-party script
modification [51]. While SRI is not designed specifically for OSN links, it
demonstrates how integrity checking can be formalized and automated at scale.
However, cryptographic integrity mechanisms must be adapted carefully for
OSN link monitoring because URLs may contain tracking parameters, shorteners, or
legitimate updates that change the URL string without necessarily indicating malicious
intent. This creates a need for canonicalization policies, parameter normalization, and
rules that separate “expected edits” from suspicious substitutions. Research on web
integrity and trusted logging suggests that auditability knowing when and how a link
changed can be as important as detecting that it changed [42], [52]. For DILI, this
motivates integrity policies that combine cryptographic baselines with behavioral
```
signals (e.g., redirect shifts, domain reputation changes, or suspicious lexical drift).
```
2.1.12.3 Platform-Scale Monitoring and Operational Constraints
At platform scale, continuous verification must balance detection accuracy
with cost, since repeatedly expanding redirects and scanning destinations can be
compute-intensive. Systems often apply tiered monitoring, where high-risk content
```
(new domains, high-velocity shares, or edited posts) is prioritized for deeper analysis.
```
This prioritization is supported by research showing that threat campaigns exhibit
characteristic propagation patterns, including bursts of posting and re-use of URL
infrastructure across accounts [38], [40]. By aligning resource allocation with risk
29
scoring, platforms can increase coverage without scanning every link at the same
depth.
Operationally, real-time monitoring must also consider adversarial adaptation.
Attackers may use cloaking, returning benign content to scanners while serving
malicious payloads to real users, or may gate phishing pages behind CAPTCHAs and
dynamic JavaScript challenges. Literature on web malware and phishing measurement
highlights that robust detection often requires multiple vantage points and repeated
observations across time to reveal conditional malicious behavior [33], [48].
2.1.13 COMPARATIVE ANALYSIS OF RELATED SYSTEMS
Several systems have been proposed to detect phishing, malicious URLs, and
spam in real time using both client-side and server-side signals. Stream-processing
approaches analyze large volumes of URLs as they appear in messages and feeds,
applying lexical features, reputation checks, and classification models to identify
threats early [34], [38]. Other approaches prioritize lightweight classification using
only the URL string, enabling efficient deployment where network-based crawling is
expensive or restricted. This diversity reflects different tradeoffs between accuracy,
latency, and resource cost, which is important for OSNs that must protect users
without slowing down content delivery.
Comparatively, DILI emphasizes a distinct threat: illegal link injections and
post-publication link manipulation, where the key risk is not only that a URL is
malicious, but that the link state changes after users have already formed trust.
Traditional systems focused on “new URL detection” may miss cases where the
original post contained a benign link but later became harmful. Therefore, literature
supports complementing initial URL classification with integrity-aware monitoring
that detects destination drift, redirect-chain changes, and edits that alter a link’s
effective target [15], [29], [32]. This framing allows DILI to be positioned as a
lifecycle-oriented defense rather than a click-time-only classifier.
2.1.13.1 Client-Side vs. Server-Side Detection Tradeoffs
Client-side defenses such as browser warnings and extensions benefit from
proximity to the user and can provide immediate feedback at navigation time. They
30
can also incorporate contextual signals like user interaction patterns and browser
telemetry. However, client-side approaches suffer from inconsistent adoption, limited
visibility into OSN editing history, and difficulty enforcing protection uniformly for
all users [6], [47]. These limitations are significant in OSNs, where attackers exploit
platform-level features rather than browser vulnerabilities alone.
Server-side detection systems operate at the platform level and can leverage
richer signals such as edit logs, account reputation, content propagation graphs, and
historical link states. They also enable consistent enforcement across the user base by
removing or flagging malicious content centrally. Prior studies on spam filtering and
```
large-scale malware spread in social networks show that network-level signals (e.g.,
```
```
coordinated posting and abnormal sharing patterns) improve detection accuracy
```
beyond URL-only features [38], [40]. This supports DILI’s orientation toward
platform-scale monitoring that can identify illegal link injections based on integrity
violations and abnormal link evolution.
2.1.13.2 Datasets, Ground Truth, and Evaluation Practices
A common challenge across malicious URL detection systems is obtaining
reliable ground truth labels. Many studies depend on blacklists, community reports, or
delayed incident confirmations, which can introduce labeling bias and time lag.
Research emphasizes that evaluations should consider adversarial conditions,
including previously unseen domains, short-lived campaigns, and redirect-based
cloaking that breaks naive crawlers [34], [33]. Without these considerations, a system
may appear accurate in offline testing but fail under real OSN attack dynamics.
Evaluation in the context of illegal link injection requires additional metrics
beyond standard malicious/benign classification accuracy. Because the threat involves
change over time, integrity-based metrics such as “time-to-detect after edit,”
“destination drift sensitivity,” and “false positive rate for benign edits” become
essential. Studies on spam filtering services and phishing measurement suggest that
practical systems must measure detection latency and operational precision under
heavy load [38], [48]. Therefore, DILI’s comparative evaluation can be strengthened
by aligning test design with these established practices and explicitly measuring
post-publication link change detection.
31
2.1.14 SYNTHESIS OF RELATED LITERATURE
The reviewed literature consistently shows that OSNs amplify link-based
threats due to high connectivity, trust-based interactions, and rapid content
propagation. Phishing and social engineering remain effective because users often
prioritize familiarity and urgency cues over careful verification of URLs and domains
[35]. At the same time, technical mechanisms like URL obfuscation, typosquatting,
and redirect chains reduce the effectiveness of simple visual inspection and basic
blacklist approaches [32], [33]. These findings explain why OSNs are persistent
targets for attackers and why platform defenses must evolve beyond static filtering.
Across studies, a recurring theme is that effective defenses require layered
detection that combines reputation intelligence, feature-based URL analysis, and
behavioral monitoring. Machine learning models can detect suspicious patterns even
when the domain is newly created, while redirect-chain analysis can reveal hidden
destinations that obfuscation attempts to conceal [6], [34], [38]. Browser defenses
reduce harm but cannot fully address OSN-specific threats like post-edit link
substitution. Consequently, the literature supports a move toward continuous
monitoring and integrity-aware verification, which directly motivates the DILI
system’s core design.
2.1.14.1 Research Gaps and Implications for OSN Link Integrity
A key gap highlighted by the literature is the limited focus on post-publication
integrity monitoring in many mainstream defenses. While much work emphasizes
detecting whether a URL is malicious at first observation, fewer solutions treat link
evolution as a first-class signal, even though OSNs allow edits and attackers exploit
lifecycle changes [15], [29]. This gap becomes more critical when benign content is
used as a “trust bootstrap” and later weaponized by injecting a malicious destination.
In such scenarios, time and sequence matter, and a defense must compare the current
link behavior to previously observed states.
Another implication is that integrity monitoring must be explainable and
operationally realistic. OSN platforms require defenses that minimize false positives,
since benign edits are common and aggressive blocking can harm user experience.
Research on security usability and phishing defenses suggests that warnings and
32
interventions must be precise and context-aware to be effective at scale [37], [53].
This supports DILI’s need to combine integrity signals with contextual indicators such
as redirect drift, sudden reputation changes, and suspicious propagation behavior
rather than relying on a single heuristic.
2.1.14.2 Alignment of Literature with the DILI System
The synthesis indicates strong support for DILI’s emphasis on detecting illegal
link injections through continuous validation and behavioral observation. Literature on
redirect evasion highlights that the full chain must be analyzed and that attackers adapt
quickly to static filters [33], [38]. Research on OSN malware spread demonstrates that
propagation patterns and account behavior can provide additional detection power
beyond URL structure alone [40]. These findings justify a DILI architecture that
integrates integrity baselines, redirect-chain analysis, and platform-level monitoring
signals.
Furthermore, cryptography and integrity concepts provide a principled
foundation for verifying whether posted content remains unchanged, while web
standards like SRI demonstrate the feasibility of automated integrity verification at
scale [36], [51]. Although DILI focuses on user-shared URLs rather than subresource
scripts, the same integrity logic applies: a trusted reference should not silently change
into an unsafe destination. Therefore, the literature collectively supports DILI’s
contribution as a system that addresses a practical OSN gap link integrity after
publication—while aligning with established approaches in phishing detection, URL
reputation, and behavioral security monitoring [34], [38].
2.1.15 ONLINE SOCIAL NETWORK COUNTERMEASURES AGAINST LINK
ABUSE
OSN platforms deploy multiple countermeasures to reduce malicious link
distribution, including automated moderation, URL scanning pipelines, account
reputation scoring, and rate-limiting of suspicious posting behavior. These defenses
attempt to detect both harmful destinations and coordinated campaigns that use many
accounts to push the same link. Research indicates that malware and spam campaigns
33
in social networks often exhibit repeatable patterns, such as bursts of new account
creation, repeated URL reuse, and abnormal sharing behavior that differs from organic
diffusion [40], [38]. By combining content signals with graph-based signals, OSNs
can reduce the reach of malicious links before they become viral.
However, OSN countermeasures must also address adversarial strategies that
exploit trust and platform mechanics. Attackers often hijack legitimate accounts to
inherit reputation and bypass basic filters, or they may “age” accounts before
launching campaigns to appear normal. Literature on social spam and phishing in
OSNs emphasizes that attackers benefit from social proof, where users are more likely
to click links shared by friends or familiar pages [25], [31]. This means link safety
cannot be treated purely as a URL property, because the surrounding social context
strongly influences user risk. In response, integrity-focused systems like DILI can
serve as a complementary control by flagging suspicious link changes even when the
surrounding account appears trustworthy.
2.1.15.1 User-Facing Warnings, Friction, and Security UX
User-facing interventions such as warning interstitials, “this link may be
unsafe” labels, and friction mechanisms that require extra confirmation are widely
used to reduce click-through on suspicious links. Anti-phishing tool evaluations show
that well-designed warnings can reduce successful attacks, but effectiveness depends
on timing, clarity, and user trust in the warning itself [37]. In OSNs, friction can be
applied selectively, such as limiting resharing for newly reported URLs or prompting
users when a link has been edited after publication. This approach is consistent with
the idea that security interventions should be risk-based rather than universal, avoiding
unnecessary disruption for benign content.
Nevertheless, user warnings have limitations when attackers rely on deception
and social engineering rather than technical exploits. Social engineering research notes
that urgency cues, fear, and reward framing can override cautious decision-making,
especially when the message appears to come from a trusted contact [35]. Attackers
can also design content to look like normal posts and distribute it through
compromised accounts, reducing suspicion. Therefore, user-facing controls are
strongest when paired with backend detection and integrity monitoring that reduces
exposure before the user must make a decision. DILI contributes to this layered
34
defense by detecting illegal link injections early enough to trigger warnings, removal,
or restricted distribution.
2.2 RELATED SYSTEM
The features and functions of DILI: A Browser Extension for Detecting Illegal
Link Injections in Edited Facebook Links and Malicious Redirects align with the
general capabilities found in URL safety tools and redirect-monitoring browser
extensions. Existing solutions can detect malicious URLs, trace redirect chains, and
block unsafe websites, but they do not provide real-time monitoring of Facebook posts
nor the ability to identify edited or injected links within social media content.
The proposed system integrates three major categories relevant to online
security tools: URL Threat Detection Systems, Redirect Analysis Extensions, and
Browser-Based Anti-Phishing Tools. These technologies contribute to the foundational
concepts of link safety but remain limited in detecting silent link manipulations inside
edited Facebook posts. DILI addresses this gap by combining real-time post
monitoring, link-version comparison, and suspicious redirect detection, offering a
level of protection not present in current tools.
a. NETCRAFT
35
Figure 1. Netcraft
Netcraft is a browser extension that detects and blocks phishing
websites, malicious URLs, and unsafe redirects. It analyzes visited links in real
time against a phishing database. However, it cannot monitor Facebook posts
for edited or injected links.
b. GOOGLE SAFE BROWSING
Figure 2. Google Safe Browsing
Google Safe Browsing identifies dangerous websites and phishing
pages by checking visited links against its constantly updated database. While
it protects users from malicious URLs, it does not track link edits within social
media posts or alert users to silent modifications in Facebook links.
c. MALWAREBYTES
36
Figure 3. Malwarebytes
Malwarebytes Browser Guard blocks malicious links and suspicious
redirects using behavior-based analysis. It prevents unsafe resources from
loading, but it cannot monitor changes in Facebook posts or detect links that
were replaced after being published.
d. REDIRECT PATH
Figure 4. Redirect Path
Redirect Path detects HTTP redirects, meta refreshes, and
JavaScript-based redirects. It helps identify multi-step redirect chains, but it
does not provide alerts for illegal link injections in Facebook posts or track
edits over time.
e. BITDEFENDER
37
Figure 5. Bitdefender
Bitdefender TrafficLight filters URLs and blocks phishing, tracking,
and malware domains. While it indicates unsafe pages, it cannot detect or
compare the original vs. edited links in social media posts, leaving users
vulnerable to silent injections.
f. LINK REDIRECT TRACE
Figure 6. Link Redirect Trace
Link Redirect Trace visualizes all redirect steps for a clicked URL,
showing headers and final destinations. It is useful for detecting hidden
redirects but cannot detect edited Facebook links or alert users before clicking.
Table 1. Comparison of Related Systems
38
Systems NETCRAFT GOOGLE
SAFE
BROWSIN
G
MALWAR
EBYTES
REDIRECT
PATH
BITDEFEN
DER
LINK
REDIRECT
DILI
39
Detects
Malicious
URLs
✓ ✓ ✓ ✕ ✓ ✕ ✓
Detects
Redirect
Chains
✕ ✕ ✓ ✓ ✓ ✓ ✓
Real-Time
Monitoring
of
Facebook
Links
✕ ✕ ✕ ✕ ✕ ✕ ✓
Detects
Edited /
Injected
Links in
Posts
✕ ✕ ✕ ✕ ✕ ✕ ✓
Alerts
Users
Before
Clicking
✓ ✓ ✓ ✕ ✓ ✕ ✓
User
Feedback /
Reputation
-Based
Detection
✓ ✓ ✓ ✓ ✓ ✕ ✕
The matrix reveals that most existing systems provide essential security
features, such as detecting malicious URLs and redirect chains. However, to stand out,
a system must offer real-time monitoring of Facebook links, the detection of edited or
injected links, and the ability to alert users before clicking. Only DILI integrates all of
these capabilities, focusing specifically on Facebook links. While DILI operates only
when the browser is open, it combines malicious URL detection, redirect tracking, and
post-edit monitoring in a unified solution. All of the related systems are browser
extensions, making them convenient and widely accessible. Since most existing
systems cannot detect illegal link injections in social media posts, DILI addresses this
critical gap, offering enhanced protection against silent link manipulations.
However, DILI has its limitations. It is limited to Facebook, not supporting
other social media platforms such as Instagram, Twitter/X, or TikTok. It also lacks
40
Real-Time
Blacklist
Updates
✓ ✓ ✓ ✕ ✓ ✕ ✕
Phishing
Reporting
✓ ✕ ✕ ✕ ✕ ✕
PLATFOR
M
BROWSE
R
EXTENSI
ON
BROWSER
EXTENSI
ON
BROWSE
R
EXTENSI
ON
BROWSE
R
EXTENSI
ON
BROWSE
R
EXTENSI
ON
BROWSE
R
EXTENSI
ON
BROW
SER
EXTE
NSION
mobile support and is designed only for Chromium-based browsers, excluding
compatibility with non-Chromium browsers like Firefox and Safari. Additionally,
DILI does not have features like real-time blacklist updates, user
feedback/reputation-based detection, or cloud-based scanning, which are available in
some of the other systems. Despite these limitations, DILI is a highly effective tool for
its specific focus on Facebook, offering enhanced protection against post-publication
link alterations.
41
CHAPTER 3
FRAMEWORK AND METHODOLOGY
3.1 Conceptual Framework
The conceptual framework of this study illustrates the underlying structure,
```
operational flow, and real-time detection logic of the DILI (Detecting Illegal Link
```
```
Injections) browser extension. DILI is designed to monitor, analyze, and evaluate the
```
integrity and safety of hyperlinks embedded within the Facebook environment, where
link manipulation, redirect-based attacks, and phishing attempts commonly occur. The
```
framework follows the Input-Process-Output (IPO) model, detailing how DILI’s
```
multi-layered detection logic will work sequentially to ensure continuous, proactive
protection. This structure highlights the interdependencies between the system's core
acquisition, processing, and output components.
42
I. Input Stage
The Input stage consists of the data and events that DILI will acquire from the user’s
active Facebook session. These inputs initiate the system’s monitoring and analysis
cycle.
● Scanned Facebook Posts.
The first input to the system is the Facebook post itself. DILI will scan posts
appearing in the user’s feed, groups, comments, Marketplace listings, and
related content areas to determine whether they contain hyperlinks.
● Extracted Hyperlinks.
Once a post is identified as containing a hyperlink, the system will extract the
URL and related hyperlink attributes for processing.
● Detected Post Edits and User Interaction Signals.
DILI will monitor whether the post or hyperlink has been edited after the
initial scan. It will also observe user interaction signals, such as hover or click
intent, to enable a final link check before navigation.
These inputs are interrelated. The post provides the content source, the hyperlink
becomes the object of analysis, and the detection of edits or interaction events
determines when re-analysis must occur. Thus, the Input stage supplies the raw data
that triggers all succeeding system operations.
II. Process Stage: Multi-Layered Protection Engine
43
This stage represents the core detection and analysis logic, segmented into four
distinct, integrated layers:
Layer 1: Detection Processes
This layer handles the initial capture and tracking of hyperlink-related activity
within Facebook posts.
● Post Scanning: Will examine Facebook posts, comments, Marketplace
listings, and group content to determine whether hyperlink elements are
present.
● Hyperlink Detection and Extraction: Will identify and extract embedded
URLs and related hyperlink attributes for monitoring and analysis.
● Content Update Detection: Will monitor posts for edits or changes in
hyperlink-related content after the original scan.
● Hover and Click-Intent Monitoring: Will observe user interaction signals to
prepare the system for real-time checking before navigation.
```
Layer 2: Analysis Processes (Integrity Check)
```
This layer performs deeper inspection of the hyperlink to verify whether it
remains unchanged after first detection. It focuses on preserving link integrity and
identifying suspicious modifications before the user interacts with the link.
● Hashing Engine: Will generate cryptographic hash values from the
hyperlink’s critical attributes to create the original baseline reference upon first
detection.
● Re-Hash and Change Comparison: Will recalculate and compare the current
hash with the stored baseline hash to verify link consistency and detect
possible unauthorized modifications.
44
● Pre-Click Link Validation: Will re-evaluate the hyperlink at the moment of
user interaction to ensure that the most recent link state is assessed before
navigation occurs.
● Redirect Chain Mapping: Will reconstruct the full redirect path of a
hyperlink, revealing multi-step or cloaked redirections commonly used in
phishing and deceptive link attacks.
Layer 3: Threat Evaluation
This layer determines whether the detected hyperlink behavior or modification
poses a real security threat. It combines threat intelligence and rule-based analysis to
assess the seriousness of the detected activity.
● API Checks: Will query Google Safe Browsing and PhishTank to verify
whether the hyperlink or redirected destination is known to be malicious or
phishing-related.
● Heuristic Domain Analysis: Will examine domain reputation, SSL certificate
presence, domain structure, and URL anomalies to identify suspicious
characteristics.
● Redirect Pattern Analysis: Will inspect redirect behavior to detect abnormal,
excessive, or misleading redirect sequences associated with phishing attacks.
Layer 4: Decision Processes
This layer generates the final judgment of the system by combining the results
of the integrity check and threat evaluation.
45
Risk Score Computation: Will calculate the final risk level of the hyperlink based on
detected integrity issues, redirect behavior, heuristic findings, and threat intelligence
results.
Safety Classification: Will classify the hyperlink as Safe, Caution, or Dangerous
according to the computed risk score.
Browser Action Logic: Will determine whether the system should allow navigation,
display a warning, or block access to the hyperlink.
III. Output Stage: User Protection and Synthesis
This stage presents the outputs that DILI will provide after analysis and
decision-making.
● Real-Time Warning UI: Will display immediate warning messages when
suspicious or dangerous links are detected.
● Navigation Blocking: Will prevent access to highly dangerous destinations
when necessary.
● Link Safety Labels: Will provide visual safety indicators such as Safe,
Caution, or Dangerous.
● Logged Incidents: Will store detected link edits, suspicious redirects, and
related incidents in local browser storage.
● Continuous Feedback Loop: Will allow the system to continue monitoring
the Facebook page for further updates, enabling repeated checking whenever
content changes.
46
Synthesis
This conceptual framework shows how DILI will function as a layered and
continuous browser-based protection system. Using the IPO model, it explains how
the system will gather hyperlink-related input, process it through detection, integrity
checking, threat evaluation, and decision-making, and produce real-time outputs that
protect the user from edited hyperlinks, redirect-based attacks, and phishing attempts.
The operational flow further strengthens the framework by showing the relationship
among the phases of the system, beginning from post scanning, hyperlink extraction,
and baseline hashing, up to risk scoring and final system response.
3.2 Methodology
Figure 8. Agile Software Development
DILI will be developed using the Agile Software Development Methodology,
an iterative and highly flexible approach widely adopted for modern software projects.
Agile emphasizes continuous collaboration, incremental development, and the ability
to adapt to changing requirements throughout the project lifecycle. This methodology
47
is especially appropriate for applications involving cybersecurity and real-time
detection such as DILI, where system requirements must evolve as new threat
behaviors, redirect patterns, and user interaction issues are discovered.
Agile divides the development cycle into short, manageable phases known as
sprints, typically one to four weeks long. Each sprint involves planning, design,
implementation, testing, and evaluation, resulting in a functional software increment
by its conclusion. For DILI, these cycles will be used to progressively refine system
components such as DOM monitoring, link integrity verification, redirect chain
analysis, and threat intelligence checking.
The Agile Manifesto highlights several guiding principles central to this approach:
● Prioritizing individuals and interactions over rigid processes and tools.
● Valuing working software over extensive documentation.
● Focusing on collaboration with stakeholders rather than strict contract
conditions.
● Responding to change instead of following a fixed plan.
Applying Agile to DILI enables early detection of design issues and efficient
integration of improvements at each iteration. Frequent evaluations ensure that core
functionalities, such as the detection of edited hyperlinks and malicious redirect
chains, perform reliably in real-world browsing environments. Continuous user and
adviser feedback during sprint reviews contribute to refining warning messages,
improving UI design clarity, and optimizing threat-detection algorithms. This
incremental and adaptive process ensures that the final system is user-centered,
responsive, and effective.
Development Tools and Environment
48
DILI will be developed as a Chrome/Chromium browser extension under
Manifest V3, using the following technologies:
```
● JavaScript (ES6): Core logic for monitoring, hashing, redirect tracing, and
```
detection.
● HTML/CSS: Extension popup UI and warning interface design.
● Chrome Extension APIs: For DOM access, background scripts, and
permission handling.
● Fetch API: For contacting external APIs like Google Safe Browsing and
PhishTank.
● Crypto API: Used specifically for generating cryptographic hashes of the
```
link's critical DOM attributes (e.g., href) to ensure immutable link integrity.
```
This is the foundation of the post-editing detection mechanism.
● Node.js & npm: Supporting development tools and testing scripts.
● Visual Studio Code: Coding environment.
● Git & GitHub: Version control.
● Google Safe Browsing API: Used in the threat evaluation layer for verifying
known malicious or deceptive URLs.
● PhishTank API: Used for cross-checking known phishing domains.
Evaluation Strategy
To assess the effectiveness, usability, and performance of the DILI browser
extension, the following evaluation methods will be implemented:
Usability Testing
Usability testing will involve 10–15 non-technical users, such as students and
staff familiar with basic Facebook usage. This sample size is deemed sufficient for a
```
proof-of-concept (POC) study focused on User-Centric Design (UCD) validation.
```
Participants will be asked to browse simulated Facebook content containing a mix of
49
safe links, altered links, and malicious redirecting URLs. They will interpret system
warnings, interact with the popup interface, and attempt to navigate links flagged by
the extension.
Metrics to be collected:
```
● Task completion rate (e.g., identifying which links are safe)
```
● Average time to detect or respond to warnings
● User satisfaction scores using a Likert-scale survey
```
● System Usability Scale (SUS) assessment
```
Functional and Performance Testing
The extension will be tested against approximately 20 representative sample
URLs. This set includes a diversity of cases necessary to establish baseline
```
performance:
```
```
● Legitimate Facebook links (True Negatives)
```
```
● Links edited after posting (link-injection cases)
```
● URLs with multi-step redirects
```
● Known malicious URLs (from Safe Browsing and PhishTank)
```
Metrics to be measured:
```
● Detection rate (True Positives / Total Threats)
```
```
● False positive rate (critical metric for usability, ensuring benign links are not
```
```
flagged)
```
● False negative rate
50
● CPU and memory usage during real-time monitoring
● Latency in detection and redirect analysis
```
The threat intelligence APIs (Google Safe Browsing, PhishTank) will only be
```
```
called during the evaluation phase or after DILI's internal checks (hashing, redirect
```
```
analysis) indicate a potential threat, mitigating concerns regarding excessive API
```
usage or rate limits.
These metrics are standard in web security research and will indicate the tool’s
reliability and efficiency.
Feedback Integration
At the end of each sprint, feedback from test users, research advisers, and
evaluators will be reviewed to improve:
● UI layout and readability of warnings
● Clarity of risk classifications
● Speed of redirect detection
● Hash comparison logic
● Responsiveness of the extension popup
Improvements will be incorporated before the start of the next sprint, following
Agile’s continuous improvement model.
Testing Environment
Development and evaluation will be conducted in a controlled simulation of
real-world Facebook browsing:
● Test pages will replicate typical Facebook posts containing links.
51
```
● Redirect tests will mirror common phishing patterns (e.g., multi-hop links,
```
```
cloaked URLs).
```
● Click-time protection will be tested through mock interactions.
● The behavior of edited links will be simulated by dynamically modifying
content in test posts using browser developer tools.
Browser activities such as scrolling, clicking, and navigating will be reproduced in a
manner similar to how users interact with Facebook in everyday scenarios.
3.3 Ethical Considerations
The development and deployment of DILI, a client-side security tool that
interacts with a major social media platform, requires adherence to stringent ethical
standards. The core ethical principle guiding this research is to prioritize user safety
and privacy while maintaining system transparency.
3.3.1 Data Privacy and Minimization
The primary ethical consideration is data handling. DILI is engineered to
comply with a principle of Data Minimization:
1. Non-Collection of Personally Identifiable Information (PII): The extension
```
will only access and process the technical attributes of hyperlinks (e.g., href
```
```
value, anchor text). It will never collect, store, or transmit any user-specific
```
data, such as usernames, passwords, post content, messages, comments,
session cookies, or browsing history.
2. Local Storage of Hashes: The cryptographic hashes used for integrity checks
```
(Layer 2) and the corresponding safety status are stored exclusively in the
```
user's local browser storage. This data is never sent to the researchers or a
52
third-party server, ensuring the integrity data remains private and confined to
the user’s device.
3.3.2 Transparency and User Consent
In accordance with ethical guidelines for client-side applications, DILI will ensure full
```
transparency:
```
1. Explicit Consent: Users must explicitly install the browser extension, which
serves as clear, informed consent for the system to monitor the DOM
```
(Document Object Model) of the Facebook environment.
```
2. Clear Functionality Disclosure: The extension description and internal
```
documentation will clearly state what the system monitors (hyperlink changes)
```
```
and where it operates (Facebook newsfeed, groups, etc.), establishing an
```
unambiguous understanding of its security role.
3.3.3 Non-Malicious Intent and Non-Interference
The project is designed solely for defensive purposes:
1. Defensive Intent: The system's purpose is to protect end-users from cyber
exploitation, aligning with the highest standards of cybersecurity ethics.
2. Non-Violation of Terms of Service (TOS): DILI avoids excessive scraping,
rate limiting, or any activity that would negatively impact Facebook's
performance or violate platform TOS, framing the extension as an added,
non-invasive security layer that benefits the user. The system's operation is
confined to the user’s browser environment and does not attempt to
reverse-engineer or exploit Facebook’s proprietary algorithms or data
structures.
5354