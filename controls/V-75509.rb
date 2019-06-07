control "V-75509" do
  title "All persistent disk partitions must implement cryptographic mechanisms
to prevent unauthorized disclosure or modification of all information that
requires at rest protection."
  desc  "Ubuntu operating systems handling data requiring \"data at rest\"
protections must employ cryptographic mechanisms to prevent unauthorized
disclosure and modification of the information at rest.

    Selection of a cryptographic mechanism is based on the need to protect the
integrity of organizational information. The strength of the mechanism is
commensurate with the security category and/or classification of the
information. Organizations have the flexibility to either encrypt all
information on storage devices (i.e., full disk encryption) or encrypt specific
data structures (e.g., files, records, or fields).


  "
  impact 0.7
  tag "gtitle": "SRG-OS-000185-GPOS-00079"
  tag "satisfies": ["SRG-OS-000185-GPOS-00079", "SRG-OS-000404-GPOS-00183",
"SRG-OS-000405-GPOS-00184"]
  tag "gid": "V-75509"
  tag "rid": "SV-90189r1_rule"
  tag "stig_id": "UBTU-16-010400"
  tag "fix_id": "F-82137r1_fix"
  tag "cci": ["CCI-001199", "CCI-002475", "CCI-002476"]
  tag "nist": ["SC-28", "SC-28 (1)", "SC-28 (1)", "Rev_4"]
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
  desc "check", "Verify the Ubuntu operating system prevents unauthorized
disclosure or modification of all information requiring at rest protection by
using disk encryption.

If there is a documented and approved reason for not having data-at-rest
encryption, this requirement is Not Applicable.

Determine the partition layout for the system with the following command:

# fdisk –l

Verify that the system partitions are all encrypted with the following command:

# more /etc/crypttab

Every persistent disk partition present must have an entry in the file. If any
partitions other than pseudo file systems (such as /proc or /sys) are not
listed, this is a finding."
  desc "fix", "Configure the Ubuntu operating system to prevent unauthorized
modification of all information at rest by using disk encryption.

Encrypting a partition in an already-installed system is more difficult,
because you need to resize and change existing partitions. To encrypt an entire
partition, dedicate a partition for encryption in the partition layout."

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

