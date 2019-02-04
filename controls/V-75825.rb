control "V-75825" do
  title "The Ubuntu operating system must display the Standard Mandatory DoD
Notice and Consent Banner before granting local or remote access to the system
via a ssh logon and the user must acknowledge the usage conditions and take
explicit actions to log on for further access."
  desc  "Display of a standardized and approved use notification before
granting access to the Ubuntu operating system ensures privacy and security
notification verbiage used is consistent with applicable federal laws,
Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces
with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with applicable DoD policy. Use
the following verbiage for Ubuntu operating systems that can accommodate
banners of 1300 characters:

    \"You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details.\"

    Use the following verbiage for Ubuntu operating systems that have severe
limitations on the number of characters that can be displayed in the banner:

    \"I've read and consent to terms in IS user agreem't.\"
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000023-GPOS-00006"
  tag "gid": "V-75825"
  tag "rid": "SV-90505r3_rule"
  tag "stig_id": "UBTU-16-030210"
  tag "fix_id": "F-82455r2_fix"
  tag "cci": ["CCI-000048"]
  tag "nist": ["AC-8 a", "Rev_4"]
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
  desc "check", "Verify the Ubuntu operating system displays the Standard
Mandatory DoD Notice and Consent Banner before granting access to the Ubuntu
operating system via a ssh logon.

Check that the Ubuntu operating system displays the Standard Mandatory DoD
Notice and Consent Banner before granting access to the Ubuntu operating system
via a ssh logon with the following command:

# grep -i banner /etc/ssh/sshd_config

Banner=/etc/issue.net

The command will return the banner option along with the name of the file that
contains the ssh banner. If the line is commented out this is a finding.

Check the specified banner file to check that it matches the Standard Mandatory
DoD Notice and Consent Banner exactly:

“You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent
to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject
to routine monitoring, interception, and search, and may be disclosed or used
for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls)
to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE
or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details.”

If the banner text does not match the Standard Mandatory DoD Notice and Consent
Banner exactly, this is a finding."
  desc "fix", "Configure the Ubuntu operating system to display the Standard
Mandatory DoD Notice and Consent Banner before granting access to the system
via SSH logon.

Edit the SSH daemon configuration \"/etc/ssh/sshd_config\" file. Uncomment the
banner keyword and configure it to point to the file that contains the correct
banner. An example of this configure is below:

Banner=/etc/issue.net

Either create the file containing the banner, or replace the text in the file
with the Standard Mandatory DoD Notice and Consent Banner. The DoD required
text is:

\"You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent
to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject
to routine monitoring, interception, and search, and may be disclosed or used
for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls)
to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE
or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details.\"

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service"
end

