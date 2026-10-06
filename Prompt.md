<?xml version="1.0" encoding="UTF-8"?>



<NADACS\_Project\_Prompt version="1.0">



&#x20;   <Project>

&#x20;       <Name>Distributed Network Anomaly Detection \&amp; Auto-Containment System (NADACS)</Name>

&#x20;       <ShortName>NADACS</ShortName>



&#x20;       <Objective>

&#x20;           Design and implement a production-inspired distributed network security platform

&#x20;           capable of detecting anomalous network behavior, evaluating threat confidence,

&#x20;           and performing automated or analyst-assisted containment while maintaining

&#x20;           tamper-evident audit records.

&#x20;       </Objective>



&#x20;       <ProblemStatement>

&#x20;           Traditional academic IDS projects rely on signature-based detection and simple

&#x20;           dashboards. NADACS must demonstrate production-style architecture including

&#x20;           distributed agents, machine learning, decision policies, containment logic,

&#x20;           and secure audit logging.

&#x20;       </ProblemStatement>

&#x20;   </Project>



&#x20;   <Architecture>



&#x20;       <Pipeline>



&#x20;           <!\[CDATA\[



&#x20;           Network Traffic

&#x20;                   │

&#x20;                   ▼

&#x20;           Capture Agents

&#x20;                   │

&#x20;                   ▼

&#x20;           Flow Feature Extraction

&#x20;                   │

&#x20;                   ▼

&#x20;           Hybrid Detection Engine

&#x20;                   │

&#x20;                   ▼

&#x20;           Decision Engine

&#x20;                   │

&#x20;                   ▼

&#x20;           Containment Layer

&#x20;                   │

&#x20;                   ▼

&#x20;           Tamper-Evident Audit Log

&#x20;                   │

&#x20;                   ▼

&#x20;           React Dashboard



&#x20;           ]]>



&#x20;       </Pipeline>



&#x20;   </Architecture>



&#x20;   <Modules>



&#x20;       <CaptureAgent>



&#x20;           <Purpose>

&#x20;               Deploy lightweight packet capture agents on different network segments.

&#x20;           </Purpose>



&#x20;           <Responsibilities>



&#x20;               <Item>Capture mirrored traffic</Item>

&#x20;               <Item>Convert packets into flows</Item>

&#x20;               <Item>Extract metadata</Item>

&#x20;               <Item>Send flow records to detection engine</Item>



&#x20;           </Responsibilities>



&#x20;           <Technology>



&#x20;               <Language>Python</Language>

&#x20;               <Libraries>



&#x20;                   <Library>Scapy</Library>

&#x20;                   <Library>PyShark</Library>



&#x20;               </Libraries>



&#x20;           </Technology>



&#x20;       </CaptureAgent>



&#x20;       <FeatureExtraction>



&#x20;           <Goal>

&#x20;               Operate on network flows instead of individual packets.

&#x20;           </Goal>



&#x20;           <ExampleFeatures>



&#x20;               <Feature>Flow Duration</Feature>

&#x20;               <Feature>Packet Count</Feature>

&#x20;               <Feature>Byte Count</Feature>

&#x20;               <Feature>Average Packet Size</Feature>

&#x20;               <Feature>Connection Rate</Feature>

&#x20;               <Feature>Destination Port</Feature>

&#x20;               <Feature>Protocol</Feature>

&#x20;               <Feature>Source IP</Feature>

&#x20;               <Feature>Destination IP</Feature>

&#x20;               <Feature>Entropy</Feature>

&#x20;               <Feature>Inter-arrival Time</Feature>



&#x20;           </ExampleFeatures>



&#x20;       </FeatureExtraction>



&#x20;       <DetectionEngine>



&#x20;           <Purpose>

&#x20;               Perform hybrid anomaly detection using statistical baselines and

&#x20;               machine learning.

&#x20;           </Purpose>



&#x20;           <StatisticalDetection>



&#x20;               <Technique>Connection Rate Analysis</Technique>

&#x20;               <Technique>Entropy Analysis</Technique>

&#x20;               <Technique>Port Scan Detection</Technique>

&#x20;               <Technique>Traffic Spike Detection</Technique>



&#x20;           </StatisticalDetection>



&#x20;           <MachineLearning>



&#x20;               <PrimaryModel>Isolation Forest</PrimaryModel>

&#x20;               <AlternativeModel>Autoencoder</AlternativeModel>



&#x20;               <Goal>

&#x20;                   Detect zero-day and previously unseen network anomalies.

&#x20;               </Goal>



&#x20;           </MachineLearning>



&#x20;           <Technology>



&#x20;               <Backend>FastAPI</Backend>

&#x20;               <MLFramework>scikit-learn</MLFramework>



&#x20;           </Technology>



&#x20;       </DetectionEngine>



&#x20;       <DecisionEngine>



&#x20;           <Purpose>

&#x20;               Evaluate anomaly confidence and determine containment policy.

&#x20;           </Purpose>



&#x20;           <Logic>



&#x20;               <HighConfidence>

&#x20;                   Automatically trigger containment.

&#x20;               </HighConfidence>



&#x20;               <MediumConfidence>

&#x20;                   Queue alert for analyst approval.

&#x20;               </MediumConfidence>



&#x20;               <LowConfidence>

&#x20;                   Log event only.

&#x20;               </LowConfidence>



&#x20;           </Logic>



&#x20;           <Technology>



&#x20;               <Framework>Node.js</Framework>

&#x20;               <Framework>Express</Framework>



&#x20;           </Technology>



&#x20;       </DecisionEngine>



&#x20;       <Containment>



&#x20;           <Purpose>

&#x20;               Simulate network isolation actions.

&#x20;           </Purpose>



&#x20;           <Methods>



&#x20;               <Method>iptables</Method>

&#x20;               <Method>Mininet</Method>

&#x20;               <Method>OpenFlow</Method>



&#x20;           </Methods>



&#x20;           <Scope>

&#x20;               Simulated enforcement only.

&#x20;               Avoid production switch integration.

&#x20;           </Scope>



&#x20;       </Containment>



&#x20;       <AuditLog>



&#x20;           <Purpose>

&#x20;               Maintain tamper-evident security logs.

&#x20;           </Purpose>



&#x20;           <Features>



&#x20;               <Feature>Hash Chaining</Feature>

&#x20;               <Feature>Immutable Audit Trail</Feature>

&#x20;               <Feature>Incident Timeline</Feature>



&#x20;           </Features>



&#x20;           <Database>PostgreSQL</Database>



&#x20;       </AuditLog>



&#x20;       <Dashboard>



&#x20;           <Framework>React</Framework>



&#x20;           <UI>Tailwind CSS</UI>



&#x20;           <Features>



&#x20;               <Feature>Live Network Flows</Feature>

&#x20;               <Feature>Threat Map</Feature>

&#x20;               <Feature>Alert Queue</Feature>

&#x20;               <Feature>Containment Approval</Feature>

&#x20;               <Feature>Audit Viewer</Feature>

&#x20;               <Feature>Analytics Dashboard</Feature>



&#x20;           </Features>



&#x20;       </Dashboard>



&#x20;   </Modules>



&#x20;   <DecisionPolicy>



&#x20;       <HighConfidence threshold="0.90">

&#x20;           Auto Contain

&#x20;       </HighConfidence>



&#x20;       <MediumConfidence threshold="0.60-0.89">

&#x20;           Require Human Approval

&#x20;       </MediumConfidence>



&#x20;       <LowConfidence threshold="Below 0.60">

&#x20;           Monitor Only

&#x20;       </LowConfidence>



&#x20;   </DecisionPolicy>



&#x20;   <EdgeCases>



&#x20;       <Case>



&#x20;           <Name>Legitimate Traffic Spikes</Name>



&#x20;           <Description>

&#x20;               Avoid classifying backup jobs, software updates,

&#x20;               or Patch Tuesday traffic as attacks.

&#x20;           </Description>



&#x20;       </Case>



&#x20;       <Case>



&#x20;           <Name>Encrypted Traffic</Name>



&#x20;           <Description>

&#x20;               Payload inspection is unavailable.

&#x20;               Detection relies on flow metadata,

&#x20;               timing characteristics,

&#x20;               packet sizes,

&#x20;               and entropy.

&#x20;           </Description>



&#x20;       </Case>



&#x20;       <Case>



&#x20;           <Name>Agent Failure</Name>



&#x20;           <Description>

&#x20;               Explicitly define fail-open or fail-closed behavior.

&#x20;           </Description>



&#x20;       </Case>



&#x20;       <Case>



&#x20;           <Name>Network Partition</Name>



&#x20;           <Description>

&#x20;               Detection continues locally until synchronization is restored.

&#x20;           </Description>



&#x20;       </Case>



&#x20;   </EdgeCases>



&#x20;   <RepositoryStructure>



&#x20;       <!\[CDATA\[



&#x20;       /nadacs

&#x20;       ├── capture-agent/

&#x20;       ├── detection-engine/

&#x20;       ├── decision-engine/

&#x20;       ├── enforcement/

&#x20;       ├── audit-log/

&#x20;       ├── dashboard/

&#x20;       ├── shared/

&#x20;       ├── docs/

&#x20;       ├── docker/

&#x20;       ├── deployment/

&#x20;       └── datasets/



&#x20;       ]]>



&#x20;   </RepositoryStructure>



&#x20;   <TechnologyStack>



&#x20;       <Backend>



&#x20;           <Language>Python</Language>

&#x20;           <Framework>FastAPI</Framework>



&#x20;       </Backend>



&#x20;       <DecisionEngine>



&#x20;           <Language>Node.js</Language>

&#x20;           <Framework>Express</Framework>



&#x20;       </DecisionEngine>



&#x20;       <Frontend>



&#x20;           <Framework>React</Framework>

&#x20;           <CSS>Tailwind CSS</CSS>



&#x20;       </Frontend>



&#x20;       <Database>PostgreSQL</Database>



&#x20;       <MachineLearning>



&#x20;           <Library>scikit-learn</Library>



&#x20;       </MachineLearning>



&#x20;       <Containerization>Docker</Containerization>



&#x20;   </TechnologyStack>



&#x20;   <ImplementationGuidelines>



&#x20;       <Guideline>

&#x20;           Prioritize modular architecture.

&#x20;       </Guideline>



&#x20;       <Guideline>

&#x20;           Prefer flow-based analysis instead of raw packet inspection.

&#x20;       </Guideline>



&#x20;       <Guideline>

&#x20;           Explain all architectural trade-offs.

&#x20;       </Guideline>



&#x20;       <Guideline>

&#x20;           Simulate enforcement rather than integrating production hardware.

&#x20;       </Guideline>



&#x20;       <Guideline>

&#x20;           Build reusable REST APIs between services.

&#x20;       </Guideline>



&#x20;       <Guideline>

&#x20;           Follow secure coding practices.

&#x20;       </Guideline>



&#x20;       <Guideline>

&#x20;           Keep components independently deployable.

&#x20;       </Guideline>



&#x20;   </ImplementationGuidelines>



&#x20;   <ExpectedOutcome>



&#x20;       Generate a complete production-style cybersecurity project including

&#x20;       distributed architecture, backend services, machine learning pipeline,

&#x20;       frontend dashboard, database schema, API contracts, Docker deployment,

&#x20;       documentation, testing strategy, and implementation roadmap suitable

&#x20;       for an IEEE publication, final-year project, internship portfolio,

&#x20;       and software engineering interviews.



&#x20;   </ExpectedOutcome>



</NADACS\_Project\_Prompt>

