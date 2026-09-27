# Corpus annotation guide

The corpus is not supplied. Use this checklist when collecting a real pilot.
Do not count the engineering smoke fixtures toward independent family coverage.

1. Record the repository or application, exact revision, schema path and rights
   evidence in a separately reviewed provenance register. `rights_reference`
   points to that immutable record. Confirm permission for training and, when
   applicable, redistribution of profiles and resulting artifacts. A public
   repository alone is insufficient evidence.
2. Assign one `application_family_id` to the original application, all forks,
   versions, deployments and generated variants. Resolve these relationships
   before computing the split. Never split related schemas to balance labels.
3. Collect metadata and bounded aggregate profiles inside the approved trusted
   boundary. Omit comments, defaults and raw values. Review identifiers for
   embedded names, email addresses, tokens and other sensitive literals before
   admitting a profile to any shared corpus. Private profiles stay private.
4. Label the column's meaning using the ordered 24 classes in
   `contracts/classifier/spec.json`. A person key is `person_identifier`; a
   product/order key is `business_identifier`. A birth date differs from an
   ordinary business timestamp. Credentials include passwords, API tokens and
   authentication secrets, regardless of their storage format. Use
   `structured_payload` for opaque JSON/arrays and `free_text` for unconstrained
   prose. `other` is a reviewed residual class, not an assertion that content is
   safe. Ambiguous or mixed-purpose columns remain unresolved until reviewed.
5. Have a second reviewer adjudicate sensitive and ambiguous labels. Record the
   actual reviewer count; the current JSON schema permits one reviewer and
   therefore cannot enforce adjudication itself. Keep disagreement reasons in
   the provenance register without copying raw values into it.
6. Freeze a dataset digest and family mapping before training. Keep natural
   naming diversity and missing profiles; do not replace real column names with
   their labels. Record application and language subgroups for later evaluation.
   Augmented variants belong only to their original family's assigned split.
7. Inspect class coverage separately in each partition. Do not move test families
   after observing model errors. New label revisions require a new dataset and
   declared evaluation run. A pilot with 100 families is still review-only.

Model confidence never authorizes `copy_original`. Qualified replacement also
requires an approved field policy, supported types and relationship/uniqueness
validation. The present pipeline cannot enable automatic acceptance.
