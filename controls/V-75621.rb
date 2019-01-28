control "V-75621" do
  title "The Ubuntu operating system must allocate audit record storage
capacity to store at least one weeks worth of audit records, when audit records
are not immediately sent to a central audit record storage facility."
  desc  "In order to ensure Ubuntu operating systems have a sufficient storage
capacity in which to write the audit logs, Ubuntu operating systems need to be
able to allocate audit record storage capacity.

    The task of allocating audit record storage capacity is usually performed
during initial installation of the Ubuntu operating system.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000341-GPOS-00132"
  tag "gid": "V-75621"
  tag "rid": "SV-90301r2_rule"
  tag "stig_id": "UBTU-16-020020"
  tag "fix_id": "F-82249r1_fix"
  tag "cci": ["CCI-001849"]
  tag "nist": ["AU-4", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "Verify the Ubuntu operating system allocates audit record
storage capacity to store at least one week's worth of audit records when audit
records are not immediately sent to a central audit record storage facility.

Determine which partition the audit records are being written to with the
following command:

# sudo grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition that audit records are written to (with the
example being /var/log/audit/) with the following command:

# df –h /var/log/audit/
/dev/sda2 24G 10.4G 13.6G 43% /var/log/audit

If the audit records are not written to a partition made specifically for audit
records (/var/log/audit is a separate partition), determine the amount of space
being used by other files in the partition with the following command:

#du –sh [audit_partition]
1.8G /var/log/audit

Note: The partition size needed to capture a week's worth of audit records is
based on the activity level of the system and the total storage capacity
available. In normal circumstances, 10.0 GB of storage space for audit records
will be sufficient.

If the audit record partition is not allocated for sufficient storage capacity,
this is a finding."
  tag "fix": "Allocate enough storage capacity for at least one week's worth of
audit records when audit records are not immediately sent to a central audit
record storage facility.

If audit records are stored on a partition made specifically for audit records,
use the \"X\" program to resize the partition with sufficient space to contain
one week's worth of audit records.

If audit records are not stored on a partition made specifically for audit
records, a new partition with sufficient amount of space will need be to be
created."
end

