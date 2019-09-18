# frozen_string_literal: true

control 'V-75393' do
  title "The Ubuntu operating system must display the Standard Mandatory DoD
Notice and Consent Banner before granting local or remote access to the system
via a graphical user logon."
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
  tag "gtitle": 'SRG-OS-000023-GPOS-00006'
  tag "satisfies": %w[SRG-OS-000023-GPOS-00006 SRG-OS-000228-GPOS-00088]
  tag "gid": 'V-75393'
  tag "rid": 'SV-90073r2_rule'
  tag "stig_id": 'UBTU-16-010020'
  tag "fix_id": 'F-82021r1_fix'
  tag "cci": %w[CCI-000048 CCI-001384 CCI-001385 CCI-001386
                CCI-001387 CCI-001388]
  tag "nist": ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', "AC-8
c 3", 'Rev_4']
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
  desc 'check', "Verify the Ubuntu operating system security patches and updates
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
  desc 'fix', "Configure the Ubuntu operating system to display the Standard
Mandatory DoD Notice and Consent Banner before granting access to the system.

Create a database that will contain the system wide graphical user logon
settings (if it does not already exist) with the following command:

# sudo touch /etc/dconf/db/local.d/01-banner-message

Add the following line to the \"[org/gnome/login-screen]\" section of the
\"/etc/dconf/db/local.d/01-banner-message\" file:

[org/gnome/login-screen]
banner-message-enable=true"

  describe command('/usr/lib/update-notifier/apt-check --human-readable') do
    its('exit_status') { should cmp 0 }
    its('stdout') { should match '^0 updates are security updates.$' }
  end

  describe 'banner-message-enable must be set to true' do
    subject { command('grep banner-message-enable /etc/dconf/db/local.d/*') }
    its('stdout') { should match /(banner-message-enable).+=.+(true)/ }
  end
end
