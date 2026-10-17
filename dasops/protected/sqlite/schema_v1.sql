CREATE TABLE metadata (
 singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1),
 identity TEXT NOT NULL CHECK(identity='das-coordination-state/v1'),
 schema_digest TEXT NOT NULL,
 authority_domain TEXT NOT NULL UNIQUE CHECK(length(authority_domain) BETWEEN 1 AND 128),
 instance_id TEXT NOT NULL CHECK(length(instance_id) BETWEEN 1 AND 128),
 authority_epoch INTEGER NOT NULL CHECK(typeof(authority_epoch)='integer' AND authority_epoch BETWEEN 1 AND 9007199254740991),
 time_floor INTEGER NOT NULL CHECK(typeof(time_floor)='integer' AND time_floor BETWEEN 0 AND 9007199254740991)
);
CREATE TABLE changes (
 authority_domain TEXT NOT NULL, project_id TEXT NOT NULL CHECK(length(project_id) BETWEEN 1 AND 128),
 change_id TEXT NOT NULL CHECK(length(change_id) BETWEEN 1 AND 128),
 status TEXT NOT NULL CHECK(status IN ('active','closing','closed','cancelled','superseded')),
 generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation BETWEEN 1 AND 9007199254740991),
 task_set_digest TEXT,
 PRIMARY KEY(authority_domain,project_id,change_id),
 FOREIGN KEY(authority_domain) REFERENCES metadata(authority_domain)
) WITHOUT ROWID;
CREATE TABLE tasks (
 authority_domain TEXT NOT NULL, project_id TEXT NOT NULL, change_id TEXT NOT NULL,
 task_id TEXT NOT NULL CHECK(length(task_id) BETWEEN 1 AND 128),
 obligation_digest TEXT NOT NULL CHECK(length(obligation_digest)=71),
 revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision BETWEEN 1 AND 9007199254740991),
 cycle INTEGER NOT NULL CHECK(typeof(cycle)='integer' AND cycle BETWEEN 1 AND 9007199254740991),
 PRIMARY KEY(authority_domain,project_id,change_id,task_id),
 FOREIGN KEY(authority_domain,project_id,change_id) REFERENCES changes(authority_domain,project_id,change_id)
) WITHOUT ROWID;
CREATE TABLE leases (
 authority_domain TEXT NOT NULL, project_id TEXT NOT NULL, change_id TEXT NOT NULL, task_id TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation BETWEEN 1 AND 9007199254740991),
 owner TEXT NOT NULL CHECK(length(owner) BETWEEN 1 AND 128),
 token_hash TEXT NOT NULL CHECK(length(token_hash)=71),
 expires_at INTEGER NOT NULL CHECK(typeof(expires_at)='integer' AND expires_at BETWEEN 1 AND 9007199254740991),
 PRIMARY KEY(authority_domain,project_id,change_id,task_id),
 FOREIGN KEY(authority_domain,project_id,change_id,task_id) REFERENCES tasks(authority_domain,project_id,change_id,task_id)
) WITHOUT ROWID;
CREATE TABLE budgets (
 authority_domain TEXT NOT NULL, budget_id TEXT NOT NULL CHECK(length(budget_id) BETWEEN 1 AND 128),
 ceiling INTEGER NOT NULL CHECK(typeof(ceiling)='integer' AND ceiling BETWEEN 1 AND 9007199254740991),
 reserved INTEGER NOT NULL CHECK(typeof(reserved)='integer' AND reserved BETWEEN 0 AND ceiling),
 PRIMARY KEY(authority_domain,budget_id)
) WITHOUT ROWID;
CREATE TABLE business_actions (
 authority_domain TEXT NOT NULL, resource_id TEXT NOT NULL CHECK(length(resource_id) BETWEEN 1 AND 128),
 action_class TEXT NOT NULL CHECK(length(action_class) BETWEEN 1 AND 128),
 business_id TEXT NOT NULL CHECK(length(business_id) BETWEEN 1 AND 128),
 project_id TEXT NOT NULL, change_id TEXT NOT NULL, task_id TEXT NOT NULL,
 cycle INTEGER NOT NULL CHECK(typeof(cycle)='integer' AND cycle BETWEEN 1 AND 9007199254740991),
 fingerprint TEXT NOT NULL CHECK(length(fingerprint)=71),
 original_actor TEXT NOT NULL CHECK(length(original_actor) BETWEEN 1 AND 128),
 state TEXT NOT NULL CHECK(state IN ('reserved','dispatched','unknown','confirmed','not_executed')),
 receipt_digest TEXT,
 PRIMARY KEY(authority_domain,resource_id,action_class,business_id),
 FOREIGN KEY(authority_domain,project_id,change_id,task_id) REFERENCES tasks(authority_domain,project_id,change_id,task_id)
) WITHOUT ROWID;
CREATE TABLE reservations (
 authority_domain TEXT NOT NULL, resource_id TEXT NOT NULL, action_class TEXT NOT NULL, business_id TEXT NOT NULL,
 budget_id TEXT NOT NULL, cost INTEGER NOT NULL CHECK(typeof(cost)='integer' AND cost BETWEEN 1 AND 9007199254740991),
 PRIMARY KEY(authority_domain,resource_id,action_class,business_id,budget_id),
 FOREIGN KEY(authority_domain,resource_id,action_class,business_id) REFERENCES business_actions(authority_domain,resource_id,action_class,business_id),
 FOREIGN KEY(authority_domain,budget_id) REFERENCES budgets(authority_domain,budget_id)
) WITHOUT ROWID;
CREATE TABLE action_payloads (
 authority_domain TEXT NOT NULL, resource_id TEXT NOT NULL, action_class TEXT NOT NULL, business_id TEXT NOT NULL,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=71),
 payload_json TEXT NOT NULL CHECK(length(CAST(payload_json AS BLOB)) BETWEEN 2 AND 65536),
 PRIMARY KEY(authority_domain,resource_id,action_class,business_id),
 FOREIGN KEY(authority_domain,resource_id,action_class,business_id) REFERENCES business_actions(authority_domain,resource_id,action_class,business_id)
) WITHOUT ROWID;
CREATE TABLE resource_observations (
 authority_domain TEXT NOT NULL, resource_id TEXT NOT NULL, action_class TEXT NOT NULL, business_id TEXT NOT NULL,
 native_digest TEXT NOT NULL CHECK(length(native_digest)=71),
 outcome TEXT NOT NULL CHECK(outcome IN ('confirmed','not_executed')),
 native_bytes BLOB NOT NULL CHECK(typeof(native_bytes)='blob' AND length(native_bytes) BETWEEN 1 AND 65536),
 PRIMARY KEY(authority_domain,resource_id,action_class,business_id,native_digest),
 FOREIGN KEY(authority_domain,resource_id,action_class,business_id) REFERENCES business_actions(authority_domain,resource_id,action_class,business_id)
) WITHOUT ROWID;
CREATE TABLE candidate_objects (
 authority_domain TEXT NOT NULL,
 candidate_digest TEXT NOT NULL CHECK(length(candidate_digest)=71),
 binding_json TEXT NOT NULL CHECK(length(CAST(binding_json AS BLOB)) BETWEEN 2 AND 1048576),
 PRIMARY KEY(authority_domain,candidate_digest),
 FOREIGN KEY(authority_domain) REFERENCES metadata(authority_domain)
) WITHOUT ROWID;
CREATE TABLE version_targets (
 authority_domain TEXT NOT NULL, resource_id TEXT NOT NULL CHECK(length(resource_id) BETWEEN 1 AND 128),
 resource_instance TEXT NOT NULL CHECK(length(resource_instance) BETWEEN 1 AND 128),
 generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation BETWEEN 1 AND 9007199254740991),
 initial_candidate_digest TEXT NOT NULL,
 candidate_digest TEXT NOT NULL,
 PRIMARY KEY(authority_domain,resource_id),
 UNIQUE(authority_domain,resource_id,resource_instance),
 FOREIGN KEY(authority_domain,candidate_digest) REFERENCES candidate_objects(authority_domain,candidate_digest),
 FOREIGN KEY(authority_domain,initial_candidate_digest) REFERENCES candidate_objects(authority_domain,candidate_digest)
) WITHOUT ROWID;
CREATE TABLE version_plans (
 authority_domain TEXT NOT NULL, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=71),
 resource_id TEXT NOT NULL, resource_instance TEXT NOT NULL,
 before_candidate TEXT NOT NULL, after_candidate TEXT NOT NULL,
 payload_json TEXT NOT NULL CHECK(length(CAST(payload_json AS BLOB)) BETWEEN 2 AND 4194304),
 PRIMARY KEY(authority_domain,plan_digest),
 FOREIGN KEY(authority_domain,resource_id,resource_instance) REFERENCES version_targets(authority_domain,resource_id,resource_instance),
 FOREIGN KEY(authority_domain,before_candidate) REFERENCES candidate_objects(authority_domain,candidate_digest),
 FOREIGN KEY(authority_domain,after_candidate) REFERENCES candidate_objects(authority_domain,candidate_digest)
) WITHOUT ROWID;
CREATE TABLE version_switch_receipts (
 authority_domain TEXT NOT NULL, resource_id TEXT NOT NULL, action_class TEXT NOT NULL, business_id TEXT NOT NULL,
 resource_instance TEXT NOT NULL, request_digest TEXT NOT NULL CHECK(length(request_digest)=71),
 plan_digest TEXT NOT NULL,
 before_generation INTEGER NOT NULL CHECK(typeof(before_generation)='integer' AND before_generation BETWEEN 1 AND 9007199254740990),
 after_generation INTEGER NOT NULL CHECK(typeof(after_generation)='integer' AND after_generation=before_generation+1),
 before_candidate TEXT NOT NULL, after_candidate TEXT NOT NULL,
 native_bytes BLOB NOT NULL CHECK(typeof(native_bytes)='blob' AND length(native_bytes) BETWEEN 1 AND 65536),
 native_digest TEXT NOT NULL CHECK(length(native_digest)=71),
 PRIMARY KEY(authority_domain,resource_id,action_class,business_id),
 UNIQUE(authority_domain,resource_id,after_generation),
 FOREIGN KEY(authority_domain,resource_id,action_class,business_id) REFERENCES business_actions(authority_domain,resource_id,action_class,business_id),
 FOREIGN KEY(authority_domain,resource_id,resource_instance) REFERENCES version_targets(authority_domain,resource_id,resource_instance),
 FOREIGN KEY(authority_domain,plan_digest) REFERENCES version_plans(authority_domain,plan_digest),
 FOREIGN KEY(authority_domain,before_candidate) REFERENCES candidate_objects(authority_domain,candidate_digest),
 FOREIGN KEY(authority_domain,after_candidate) REFERENCES candidate_objects(authority_domain,candidate_digest)
) WITHOUT ROWID;
CREATE TABLE completions (
 authority_domain TEXT NOT NULL, project_id TEXT NOT NULL, change_id TEXT NOT NULL, task_id TEXT NOT NULL,
 cycle INTEGER NOT NULL CHECK(typeof(cycle)='integer' AND cycle BETWEEN 1 AND 9007199254740991),
 revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision BETWEEN 1 AND 9007199254740991),
 evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=71),
 resource_id TEXT NOT NULL, action_class TEXT NOT NULL, business_id TEXT NOT NULL,
 receipt_digest TEXT NOT NULL CHECK(length(receipt_digest)=71),
 PRIMARY KEY(authority_domain,project_id,change_id,task_id,cycle),
 FOREIGN KEY(authority_domain,project_id,change_id,task_id) REFERENCES tasks(authority_domain,project_id,change_id,task_id),
 FOREIGN KEY(authority_domain,resource_id,action_class,business_id) REFERENCES business_actions(authority_domain,resource_id,action_class,business_id)
) WITHOUT ROWID;
CREATE TABLE completion_bindings (
 authority_domain TEXT NOT NULL, project_id TEXT NOT NULL, change_id TEXT NOT NULL, task_id TEXT NOT NULL,
 cycle INTEGER NOT NULL CHECK(typeof(cycle)='integer' AND cycle BETWEEN 1 AND 9007199254740991),
 native_bytes BLOB NOT NULL CHECK(typeof(native_bytes)='blob' AND length(native_bytes) BETWEEN 2 AND 65536),
 native_digest TEXT NOT NULL CHECK(length(native_digest)=71),
 PRIMARY KEY(authority_domain,project_id,change_id,task_id,cycle),
 FOREIGN KEY(authority_domain,project_id,change_id,task_id,cycle) REFERENCES completions(authority_domain,project_id,change_id,task_id,cycle)
) WITHOUT ROWID;
CREATE TRIGGER preserve_completion_binding BEFORE UPDATE ON completion_bindings BEGIN SELECT RAISE(ABORT,'immutable native Completion'); END;
CREATE TRIGGER preserve_completion_binding_delete BEFORE DELETE ON completion_bindings BEGIN SELECT RAISE(ABORT,'retained native Completion'); END;
CREATE TABLE audit (
 sequence INTEGER NOT NULL PRIMARY KEY,
 event TEXT NOT NULL, actor TEXT NOT NULL, body TEXT NOT NULL,
 previous_digest TEXT NOT NULL, digest TEXT NOT NULL UNIQUE
);
CREATE TRIGGER preserve_task_identity BEFORE UPDATE OF authority_domain,project_id,change_id,task_id,obligation_digest ON tasks BEGIN SELECT RAISE(ABORT,'immutable task identity/obligation'); END;
CREATE TRIGGER preserve_action_identity BEFORE UPDATE OF authority_domain,resource_id,action_class,business_id,project_id,change_id,task_id,cycle,fingerprint,original_actor ON business_actions BEGIN SELECT RAISE(ABORT,'immutable business action fingerprint'); END;
CREATE TRIGGER preserve_completion BEFORE UPDATE ON completions BEGIN SELECT RAISE(ABORT,'immutable completion'); END;
CREATE TRIGGER preserve_completion_delete BEFORE DELETE ON completions BEGIN SELECT RAISE(ABORT,'retained completion'); END;
CREATE TRIGGER preserve_audit BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TRIGGER preserve_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TRIGGER preserve_task_delete BEFORE DELETE ON tasks BEGIN SELECT RAISE(ABORT,'retained task identity'); END;
CREATE TRIGGER preserve_action_delete BEFORE DELETE ON business_actions BEGIN SELECT RAISE(ABORT,'retained business action'); END;
CREATE TRIGGER preserve_change_delete BEFORE DELETE ON changes BEGIN SELECT RAISE(ABORT,'retained change identity'); END;
CREATE TRIGGER preserve_budget_delete BEFORE DELETE ON budgets BEGIN SELECT RAISE(ABORT,'retained budget'); END;
CREATE TRIGGER preserve_reservation_delete BEFORE DELETE ON reservations BEGIN SELECT RAISE(ABORT,'retained reservation'); END;
CREATE TRIGGER preserve_change_identity BEFORE UPDATE OF authority_domain,project_id,change_id ON changes BEGIN SELECT RAISE(ABORT,'immutable change identity'); END;
CREATE TRIGGER preserve_action_payload BEFORE UPDATE ON action_payloads BEGIN SELECT RAISE(ABORT,'immutable action payload'); END;
CREATE TRIGGER preserve_action_payload_delete BEFORE DELETE ON action_payloads BEGIN SELECT RAISE(ABORT,'retained action payload'); END;
CREATE TRIGGER preserve_resource_observation BEFORE UPDATE ON resource_observations BEGIN SELECT RAISE(ABORT,'immutable resource observation'); END;
CREATE TRIGGER preserve_resource_observation_delete BEFORE DELETE ON resource_observations BEGIN SELECT RAISE(ABORT,'retained resource observation'); END;
CREATE TRIGGER preserve_candidate_object BEFORE UPDATE ON candidate_objects BEGIN SELECT RAISE(ABORT,'immutable candidate registration'); END;
CREATE TRIGGER preserve_candidate_object_delete BEFORE DELETE ON candidate_objects BEGIN SELECT RAISE(ABORT,'retained candidate registration'); END;
CREATE TRIGGER preserve_version_target_identity BEFORE UPDATE OF authority_domain,resource_id,resource_instance,initial_candidate_digest ON version_targets BEGIN SELECT RAISE(ABORT,'immutable version target instance'); END;
CREATE TRIGGER preserve_version_target_delete BEFORE DELETE ON version_targets BEGIN SELECT RAISE(ABORT,'retained version target'); END;
CREATE TRIGGER preserve_version_plan BEFORE UPDATE ON version_plans BEGIN SELECT RAISE(ABORT,'immutable version plan'); END;
CREATE TRIGGER preserve_version_plan_delete BEFORE DELETE ON version_plans BEGIN SELECT RAISE(ABORT,'retained version plan'); END;
CREATE TRIGGER preserve_version_switch BEFORE UPDATE ON version_switch_receipts BEGIN SELECT RAISE(ABORT,'immutable native version receipt'); END;
CREATE TRIGGER preserve_version_switch_delete BEFORE DELETE ON version_switch_receipts BEGIN SELECT RAISE(ABORT,'retained native version receipt'); END;
