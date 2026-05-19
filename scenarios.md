# Security Response Advisor — Scenario Library

> **Disclaimer:** These scenarios are illustrative guidance examples developed for the Multimodal Security Response Advisor prototype. They are not legal advice and do not substitute for site-specific Standard Operating Procedures, agency-level SOPs, or the judgement of licensed security professionals. All responses should be adapted to the actual deployment context and reviewed by a qualified Security Manager.
>
> All sources referenced below are publicly available Singapore government and regulatory documents as of May 2026.

---

## Scenario 1 — Gunshot Detected

**What happened**
A loud percussive sound consistent with a gunshot is captured by audio sensors near a building lobby; live CCTV shows occupants running and taking cover.

**Inputs used**

* Audio sensor (impulsive bang detection)
* Live CCTV / video feed (crowd panic, directional flight)
* Access control log (last card swipe at entry point before event)
* Panic button or intercom call from lobby staff

**Key indicators**

* Impulsive audio spike with waveform consistent with a ballistic event
* Visible crowd dispersal on CCTV within seconds of the audio trigger
* No scheduled event or authorised activity logged in the affected zone
* Intercom or panic button activated by personnel on site

**Threat level**
CRITICAL

**Recommended response**

1. Initiate building lockdown immediately — seal all access points via BMS; restrict lifts to ground
2. Dispatch all available officers to cordon the zone — contain, do not confront
3. Call Singapore Police Force (999) and SCDF (995) without delay
4. Notify Fire Safety Manager and Building Security Controller; activate Emergency Response Plan
5. Keep CCTV recording active; do not overwrite or tamper with footage
6. Do not send unarmed officers toward the suspected origin point — observe and contain only
7. **Human approval required before any officer physically enters the suspected zone**

**Why that response is proportionate**
A confirmed gunshot in an occupied building is an active threat to life. SPF's Contingency Planning and Protective Security Advisories for Workplaces (Apr 2022) mandates immediate police notification and lockdown for active threat scenarios. The PSIA limits security officers to reasonable force for self-defence only — unarmed officers must not confront a suspected armed individual. The graduated approach (contain → call SPF → do not advance) is the only proportionate posture until police arrive and assume command.

**Public sources**

* SPF Contingency Planning and Protective Security Advisories for Workplaces (Apr 2022): https://www.police.gov.sg/-/media/Spf/Files/Contingency-Planning-and-Protective-Security-Advisories-for-Workplaces-Apr-2022.ashx
  *(Also mirrored at SGSecure: https://www.sgsecure.gov.sg/docs/default-source/default-document-library/contingency-planning-and-protective-security-advisories-for-workplaces.pdf)*
* WSQ Recognise Terrorist Threats — SEC-OBS-1002-1.1 (mandatory BLU for all deployed SOs): https://www.mom.gov.sg/-/media/mom/documents/employment-practices/pwm/stc-report-on-enhanced-training-requirements-jan-2023.pdf
* Guidelines for Enhancing Building Security in Singapore (GEBSS), MHA/SPF CPS: https://www.police.gov.sg/-/media/SPF/Archived/2021-10-29/CPS/Building-Security/GEBSS.pdf
* Private Security Industry Act (PSIA) — force limitations on security officers: https://sso.agc.gov.sg/Act/PSIA2007

**Notes**

* Human approval required before any officer advances toward a suspected active shooter
* No weapons escalation by security officers; SPF firearms officers will take command on arrival
* Do not use walkie-talkies or mobile phones within 15 m of a suspected improvised device (per SPF Advisory) if incident origin is ambiguous
* All footage and access logs are potential criminal evidence — preserve under PDPA evidentiary obligations and do not delete

---

## Scenario 2 — Intrusion Sequence

**What happened**
A staff access card is rejected at a restricted server room door; 90 seconds later the door contact sensor registers a forced-open event and an interior motion sensor activates with no authorised occupant logged.

**Inputs used**

* Access control log (card swipe and rejection record, credential status)
* Door contact sensor (forced-open event)
* Motion sensor (interior activation with no logged occupant)
* CCTV (corridor view at time of entry)

**Key indicators**

* Rejected badge belonging to a terminated or suspended employee
* Door forced open within 90 seconds of badge rejection — deliberate bypass pattern
* Interior motion detected with no authorised person logged in the room
* CCTV confirms one or more individuals entering after the door opens

**Threat level**
HIGH

**Recommended response**

1. Dispatch two officers to the room — treat as active intrusion until officers confirm otherwise
2. Lock down adjacent corridors via BMS; do not lock the room itself until officers are in position
3. Notify IT Security Manager concurrently — isolate network ports in the room if critical infrastructure is at risk
4. Notify Building Security Controller and log each action with timestamp
5. Call SPF (999) **only after officers on site confirm the presence of intruder(s)** — avoid false-alarm report unless confirmed
6. Preserve access log, door sensor record, and CCTV footage immediately; do not overwrite
7. File a PLRD incident report if intrusion is confirmed

**Why that response is proportionate**
The three-signal sequence (rejected credential → forced door → interior motion) is a high-confidence intrusion pattern. Dispatching officers is warranted but calling police before on-site confirmation avoids unnecessary escalation and the associated regulatory risk of false police reports. WSQ Handle Security Incidents and Services (HSIS, SEC-ICM-1003-1.1) instructs officers to respond quickly, prevent suspect escape, and prevent destruction of evidence. SPF VSS Standard requires alarm events to auto-display the relevant CCTV camera for rapid operator assessment. Two-officer dispatch is proportionate to a likely active intrusion in a critical asset room.

**Public sources**

* SPF Video Surveillance System (VSS) Standard for Buildings (CPS): https://www.police.gov.sg/-/media/SPF/Knowledge-Hub/Infrastructure-Protection/VSS-Standard-for-Buildings.pdf
* WSQ Handle Security Incidents and Services (HSIS) — SEC-ICM-1003-1.1, via SPF Refresher Quiz Training Package: https://www.police.gov.sg/-/media/SPF/Files/E-services/SO/Refresher-Quiz-Training-Package.pdf
* SPF Contingency Planning Advisory (Apr 2022): https://www.police.gov.sg/-/media/Spf/Files/Contingency-Planning-and-Protective-Security-Advisories-for-Workplaces-Apr-2022.ashx
* PLRD SACE Assessment Checklist (Oct 2024): https://www.police.gov.sg/-/media/Spf/Files/E-services/SACE/SACE-Assessment-Checklists/Proposed-Amendments---Oct-2024/Proposed-Amendment-PLRD-Elective-Competencies-Evaluation-Checklist-Oct-2024.ashx

**Notes**

* Police call is gated on on-site confirmation — do not call based on sensor data alone
* If no intruder is found: log as attempted access, refer credential to HR and Security Manager, reset door hardware, submit internal report
* If personal data may have been accessed in the room: employer must assess PDPA notification obligations to PDPC
* Evidence chain must be maintained from first alert — do not access or move equipment in the room before SPF arrives if intrusion is confirmed

---

## Scenario 3 — Loitering

**What happened**
Motion sensors and CCTV at a building perimeter register the same individual appearing three or more times in the same zone over two hours, with no badge swipe, visitor registration, or identifiable legitimate purpose recorded.

**Inputs used**

* Motion sensor (repeated triggers, same zone, multiple intervals)
* CCTV (visual confirmation of same individual across timestamps)
* Access control log (no matching entry event for individual)
* Visitor management system (no registration found)

**Key indicators**

* Same person detected 3 or more times over 2 hours in a monitored perimeter zone
* No access credential or visitor log entry at any point
* Individual not engaged in a recognisable legitimate activity such as delivery, waiting, or authorised maintenance
* Possible reconnaissance behaviour: observing entry points, inspecting access hardware, photographing the building

**Threat level**
MEDIUM

**Recommended response**

1. Review CCTV footage to confirm the same individual and note all timestamps before approaching
2. Dispatch one officer to approach calmly and professionally — establish reason for presence
3. If the individual cannot account for their presence, politely request that they leave and log the interaction with a physical description
4. Increase patrol frequency in the zone for the remainder of the shift
5. **Escalate to HIGH and call SPF (999) if the individual returns after being asked to leave, or if suspicious items or devices are observed**
6. Capture a CCTV still of the individual for the record before the officer makes contact

**Why that response is proportionate**
Repeated presence without access credentials is a recognised pre-attack indicator under SPF's Contingency Planning Advisory (reconnaissance, loitering). However, loitering alone does not confirm hostile intent. A direct police call at this stage would be disproportionate and creates the risk of a false report. WSQ Deterrence training (MDCTB) and HSIS both instruct officers to use visible presence and verbal engagement as the first step. Escalation is triggered by a return after warning or by observation of a suspicious item — not by loitering alone.

**Public sources**

* SPF Contingency Planning Advisory (Apr 2022) — reconnaissance as pre-attack indicator: https://www.police.gov.sg/-/media/Spf/Files/Contingency-Planning-and-Protective-Security-Advisories-for-Workplaces-Apr-2022.ashx
* WSQ Deterrence — Manage Disorderly Conduct and Threatening Behaviour (MDCTB), Learner's Guide: https://learning.cbm.com.sg/wp-content/uploads/2024/05/WSQ-Deterrence-Learners-Guide-v1.3-3-Jan-24.pdf
* GEBSS — pre-attack indicators and surveillance detection: https://www.police.gov.sg/-/media/SPF/Archived/2021-10-29/CPS/Building-Security/GEBSS.pdf
* WSH Guidelines for the Private Security Industry (engagement conduct): https://www.sas.org.sg/wp-content/uploads/2021/06/For-Public-Consultation-Draft-WSH-Guidelines-for-Private-Security.pdf

**Notes**

* No physical restraint — officer approach must be professional and non-confrontational under the PSIA Code of Conduct
* If the individual displays or attempts to conceal a suspicious item, withdraw and escalate to CRITICAL immediately — do not attempt to inspect the item
* Log all interactions with timestamps; this record is relevant if a subsequent incident occurs

---

## Scenario 4 — Storm or Environmental Noise

**What happened**
During a heavy thunderstorm, motion sensors across multiple zones activate simultaneously and several door contact alarms trigger from vibration, with no corresponding person visible on any CCTV feed.

**Inputs used**

* Motion sensors (widespread simultaneous triggers across geographically separated zones)
* Door contact sensors (vibration-triggered activations)
* CCTV (no persons visible in any triggered zone)
* Environmental context: active thunderstorm (NEA warning or BMS weather feed)

**Key indicators**

* Sensor triggers are simultaneous or near-simultaneous across multiple zones with no single origin point
* CCTV confirms no persons present in any triggered zone
* Pattern is consistent with known false-positive profiles: heavy rain, wind, thunder vibration
* No access log events coincide with any of the sensor triggers

**Threat level**
LOW

**Recommended response**

1. Cross-reference every triggered zone against the live CCTV feed — confirm no persons present in any zone before classifying as environmental
2. Check active weather conditions via NEA (https://www.nea.gov.sg/weather) or BMS environmental feed
3. Log the event as a probable environmental false positive with supporting rationale (zones affected, weather status, CCTV outcome)
4. Maintain standard patrol schedule — no additional dispatch required
5. Continue monitoring: if any single zone shows a person on CCTV, isolate and treat that zone as a live incident regardless of weather context
6. After the storm, inspect sensors and door hardware for damage or calibration drift

**Why that response is proportionate**
Deploying officers to every simultaneously triggered zone during a storm exhausts patrol resources and degrades response quality for genuine events. SPF VSS Standard explicitly recommends data-analytic features to reduce false positives and maintain operational effectiveness. The response remains vigilant — CCTV cross-check is mandatory before classification — but avoids disproportionate resource deployment. Passive monitoring with accurate logging is the correct posture when all sensor data is explained by a known environmental cause.

**Public sources**

* SPF VSS Standard for Buildings — false positive management, analytics, UPS requirements: https://www.police.gov.sg/-/media/SPF/Knowledge-Hub/Infrastructure-Protection/VSS-Standard-for-Buildings.pdf
* SPF Contingency Planning Advisory (Apr 2022): https://www.police.gov.sg/-/media/Spf/Files/Contingency-Planning-and-Protective-Security-Advisories-for-Workplaces-Apr-2022.ashx
* NEA Weather — Singapore public weather service: https://www.nea.gov.sg/weather
* WSQ Guard and Patrol — SEC-SOP-1007-1.1 (patrol log-keeping): https://aprotraining.sg/our-courses/blu/

**Notes**

* Do not dismiss all alerts during a storm; using storm cover to mask an intrusion is a known tactic — any human figure appearing on CCTV in a triggered zone must be treated as a live incident
* Log the false-positive pattern across incidents to support sensor calibration and threshold adjustment over time
* If door hardware repeatedly triggers false positives during storms, flag for maintenance review — poorly calibrated sensors undermine the reliability of the whole detection system

---

## Scenario 5 — Sensor Tampering or System Attack

**What happened**
Two CCTV cameras covering a loading bay produce blank or uniform images (lens obstructed); within minutes the access control log records a rapid sequence of swipes on the same credential at abnormal frequency, suggesting cloned or replayed credentials.

**Inputs used**

* CCTV feed (blank, static, or artificially uniform image — obstruction detected)
* Access control log (abnormal swipe frequency, off-hours access, same credential used repeatedly)
* Motion sensor (activity in the loading bay zone while cameras are blind)
* VSS management software tamper or loss-of-image alert

**Key indicators**

* One or more cameras producing a blank or uniform image in the same zone
* Access log shows 5 or more swipes of the same credential within 2 minutes, or swipes at an entry point immediately following camera loss
* Motion detected in the zone the now-blind camera was covering
* Timing correlation between camera loss and access log anomaly — not coincidental

**Threat level**
HIGH

**Recommended response**

1. Treat camera obstruction as a deliberate hostile act — not a technical fault — until on-site officers confirm otherwise
2. Switch to any overlapping camera views to maintain visual coverage of the affected zone before dispatching
3. Dispatch two officers to the zone via a route not covered by the obstructed cameras
4. Lock down the affected entry points via BMS immediately
5. Notify IT Security or systems administrator to check for credential cloning, replay attack, or access system compromise
6. Call SPF (999) — deliberate camera obstruction combined with abnormal access activity is a strong indicator of a premeditated intrusion; **this threshold justifies police notification before on-site confirmation**
7. Preserve full access log, CCTV tamper alert, and VSS system logs as evidence
8. Do not attempt to clean or restore obstructed cameras until the zone is confirmed clear by officers

**Why that response is proportionate**
Camera obstruction combined with abnormal credential activity is a multi-signal, high-confidence indicator of a coordinated attack — not a single ambiguous event. SPF VSS Standard requires buildings to include tamper alerts, overlapping coverage, and UPS backup specifically to detect and respond to deliberate system interference. Unlike the intrusion scenario (Scenario 2), this scenario involves active system sabotage, which is itself a criminal act under the Penal Code independent of what follows — justifying police notification at the same time as dispatch, not after confirmation. PLRD SACE criteria require security agencies to have documented SOPs for equipment tampering.

**Public sources**

* SPF VSS Standard for Buildings — tamper detection, overlapping coverage, UPS, loss-of-image alerts: https://www.police.gov.sg/-/media/SPF/Knowledge-Hub/Infrastructure-Protection/VSS-Standard-for-Buildings.pdf
* SPF Contingency Planning Advisory (Apr 2022): https://www.police.gov.sg/-/media/Spf/Files/Contingency-Planning-and-Protective-Security-Advisories-for-Workplaces-Apr-2022.ashx
* PLRD SACE Elective Competencies Checklist (Oct 2024) — BWC SOP, system integrity requirements: https://www.police.gov.sg/-/media/Spf/Files/E-services/SACE/SACE-Assessment-Checklists/Proposed-Amendments---Oct-2024/Proposed-Amendment-PLRD-Elective-Competencies-Evaluation-Checklist-Oct-2024.ashx
* GEBSS — physical security layering, access control integration: https://www.police.gov.sg/-/media/SPF/Archived/2021-10-29/CPS/Building-Security/GEBSS.pdf

**Notes**

* Do not clean or touch tampered hardware before SPF forensics assessment — chain of evidence must be preserved
* If the zone contains critical IT infrastructure, notify IT Security concurrently with the police call
* If the credential used in the abnormal swipe sequence belongs to a current employee, treat as a potential insider threat and escalate to senior management and HR immediately
* Police notification is justified at the point of dispatch in this scenario — the combination of deliberate obstruction and access anomaly meets the threshold without requiring on-site confirmation

---

## Scenario 6 — Normal or Routine Activity

**What happened**
Motion sensors register activity in a common corridor during standard office hours and CCTV shows staff moving through normally; access logs show expected badge swipes from active employees.

**Inputs used**

* Motion sensor (low frequency, single zone, business hours)
* CCTV (persons visible, no anomalous behaviour)
* Access control log (valid credentials, normal swipe pattern)

**Key indicators**

* All sensor triggers correspond to visible persons on CCTV
* Badge swipes match active employee credentials with no anomalies
* Activity time and location are consistent with normal occupancy patterns for the zone and time of day
* No loitering, forced entry, camera obstruction, or out-of-hours activity

**Threat level**
LOW

**Recommended response**

1. Passive monitoring only — no dispatch required
2. Log sensor and access events as routine in the daily security report
3. Maintain scheduled patrol frequency with no change
4. VSS operator continues the standard scan pattern per SPF VSS Standard

**Why that response is proportionate**
All signals are fully explained by legitimate activity. Dispatching officers to confirmed routine events wastes patrol resources and generates alert fatigue that degrades response quality for genuine incidents. WSQ Guard and Patrol (SEC-SOP-1007-1.1) instructs officers to maintain vigilance and accurate logs while reserving active responses for genuine anomalies. Passive monitoring with thorough logging is the correct and proportionate posture for this state.

**Public sources**

* WSQ Guard and Patrol / Access Control Management — SEC-SOP-1007-1.1: https://aprotraining.sg/our-courses/blu/
* SPF VSS Standard for Buildings — standard monitoring procedures: https://www.police.gov.sg/-/media/SPF/Knowledge-Hub/Infrastructure-Protection/VSS-Standard-for-Buildings.pdf
* WSH Guidelines for the Private Security Industry — routine duties and log-keeping: https://www.sas.org.sg/wp-content/uploads/2021/06/For-Public-Consultation-Draft-WSH-Guidelines-for-Private-Security.pdf
* PLRD SACE Assessment Checklist (Oct 2024) — log quality assessed during licence audits: https://www.police.gov.sg/-/media/Spf/Files/E-services/SACE/SACE-Assessment-Checklists/Proposed-Amendments---Oct-2024/Proposed-Amendment-PLRD-Elective-Competencies-Evaluation-Checklist-Oct-2024.ashx

**Notes**

* Even in a normal state, accurate and complete logs are mandatory — PLRD SACE audits assess log quality directly
* Normal activity baselines (times, zones, credential patterns) should be recorded and used to calibrate anomaly detection thresholds
* If the same activity pattern occurs outside business hours in this zone, re-classify as MEDIUM and apply Loitering (Scenario 3) or Intrusion (Scenario 2) logic as appropriate

---

## Source index

All sources are publicly accessible Singapore government or regulatory documents verified as of May 2026.

| Document                                                                          | Issuing body        | URL                                                                                                                                                                                                    |
| --------------------------------------------------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Contingency Planning and Protective Security Advisories for Workplaces (Apr 2022) | SPF / MHA           | https://www.police.gov.sg/-/media/Spf/Files/Contingency-Planning-and-Protective-Security-Advisories-for-Workplaces-Apr-2022.ashx                                                                       |
| VSS Standard for Buildings                                                        | SPF CPS             | https://www.police.gov.sg/-/media/SPF/Knowledge-Hub/Infrastructure-Protection/VSS-Standard-for-Buildings.pdf                                                                                           |
| Guidelines for Enhancing Building Security in Singapore (GEBSS)                   | MHA / SPF CPS       | https://www.police.gov.sg/-/media/SPF/Archived/2021-10-29/CPS/Building-Security/GEBSS.pdf                                                                                                              |
| SPF Refresher Quiz Training Package (WSQ BLUs)                                    | SPF / PLRD          | https://www.police.gov.sg/-/media/SPF/Files/E-services/SO/Refresher-Quiz-Training-Package.pdf                                                                                                          |
| STC Enhanced Training Requirements Report (Jan 2023)                              | MOM / MHA           | https://www.mom.gov.sg/-/media/mom/documents/employment-practices/pwm/stc-report-on-enhanced-training-requirements-jan-2023.pdf                                                                        |
| PLRD SACE Elective Competencies Checklist (Oct 2024)                              | SPF PLRD            | https://www.police.gov.sg/-/media/Spf/Files/E-services/SACE/SACE-Assessment-Checklists/Proposed-Amendments---Oct-2024/Proposed-Amendment-PLRD-Elective-Competencies-Evaluation-Checklist-Oct-2024.ashx |
| WSQ Deterrence Learner's Guide (MDCTB)                                            | SkillsFuture / CBM  | https://learning.cbm.com.sg/wp-content/uploads/2024/05/WSQ-Deterrence-Learners-Guide-v1.3-3-Jan-24.pdf                                                                                                 |
| WSH Guidelines — Private Security Industry                                       | WSH Council / SAS   | https://www.sas.org.sg/wp-content/uploads/2021/06/For-Public-Consultation-Draft-WSH-Guidelines-for-Private-Security.pdf                                                                                |
| SCDF Emergency Response Plan Guidelines                                           | SCDF                | https://www.scdf.gov.sg/fire-safety-services-listing/emergency-response-plan                                                                                                                           |
| Private Security Industry Act (PSIA)                                              | AGC Singapore       | https://sso.agc.gov.sg/Act/PSIA2007                                                                                                                                                                    |
| NEA Weather (environmental context)                                               | NEA                 | https://www.nea.gov.sg/weather                                                                                                                                                                         |
| WSQ BLU course overview (SEC-SOP-1007-1.1)                                        | APRO / SkillsFuture | https://aprotraining.sg/our-courses/blu/                                                                                                                                                               |
