control "V-75391" do
  title "Ubuntu vendor packaged system security patches and updates must be
installed and up to date."
  desc  "Timely patching is critical for maintaining the operational
availability, confidentiality, and integrity of information technology (IT)
systems. However, failure to keep Ubuntu operating system and application
software patched is a common mistake made by IT professionals. New patches are
released daily, and it is often difficult for even experienced System
Administrators to keep abreast of all the new patches. When new weaknesses in
an Ubuntu operating system exist, patches are usually made available by the
vendor to resolve the problems. If the most recent security patches and updates
are not installed, unauthorized users may take advantage of weaknesses in the
unpatched software. The lack of prompt attention to patching could result in a
system compromise."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-75391"
  tag "rid": "SV-90071r4_rule"
  tag "stig_id": "UBTU-16-010010"
  tag "fix_id": "F-82019r4_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  desc "check", "Verify the Ubuntu operating system security patches and updates
are installed and up to date. Updates are required to be applied with a
frequency determined by the site or Program Management Office (PMO).

Obtain the list of available package security updates from Ubuntu. The URL for
updates is https://www.Ubuntu.com/usn/. It is important to note that updates
provided by Ubuntu may not be present on the system if the underlying packages
are not installed.

Check that the available package security updates have been installed on the
system with the following command:

# /usr/lib/update-notifier/apt-check --human-readable

246 packages can be updated.
0 updates are security updates.

If security package updates have not been performed on the system within the
timeframe that the site/program documentation requires, this is a finding.

Typical update frequency may be overridden by Information Assurance
Vulnerability Alert (IAVA) notifications from JFHQ-DoDIN.

If the Ubuntu operating system is in non-compliance with the Information
Assurance Vulnerability Management (IAVM) process, this is a finding."
  tag "fix": "Install the Ubuntu operating system patches or updated packages
available from Canonical within 30 days or sooner as local policy dictates."
end

