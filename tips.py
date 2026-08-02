import random

CYBERSECURITY_TIPS = [
    "Never share your OTP, PIN, or password with anyone — not even someone claiming to be your bank.",
    "Enable Two-Factor Authentication (2FA) on every account that supports it.",
    "Hover over links (or long-press on mobile) to preview the real destination before clicking.",
    "Check the sender's actual email address, not just the display name.",
    "Banks and government agencies will never ask for your PIN or password over SMS or email.",
    "Be suspicious of messages that create urgency or fear to rush your decision.",
    "Type website addresses directly into your browser instead of clicking links in messages.",
    "Use a password manager to generate and store strong, unique passwords for each account.",
    "Keep your operating system and apps updated to patch known security vulnerabilities.",
    "Avoid connecting to public Wi-Fi without a VPN when accessing sensitive accounts.",
    "Legitimate companies rarely ask you to pay fees or fines using gift cards.",
    "Double-check the spelling of a website's domain name — phishing sites often use lookalike domains.",
    "If an offer seems too good to be true (huge prizes, guaranteed returns), it probably is.",
    "Regularly review your bank and credit card statements for unauthorized transactions.",
    "Do not install remote-access software (like AnyDesk or TeamViewer) for someone who contacted you unexpectedly.",
    "Report phishing emails and messages to your email provider or local cybercrime authority.",
    "Back up important files regularly in case of ransomware or device compromise.",
    "Use official apps downloaded from verified app stores instead of links sent via SMS.",
    "Be cautious of QR codes from unknown sources — they can lead to malicious websites.",
    "Verify unexpected requests for money or gift cards from 'friends' or 'family' through a separate channel.",
    "Lock your phone and computer with a strong PIN, password, or biometric authentication.",
    "Avoid oversharing personal details (birthdate, address, mother's maiden name) on social media.",
    "Check for HTTPS and a valid padlock icon before entering payment details on a website.",
    "Log out of accounts on shared or public computers when you're done.",
    "Be wary of unsolicited tech support calls claiming your computer is infected.",
]


def get_random_tips(count=5):
    """Return a random sample of cybersecurity tips."""
    sample_size = min(count, len(CYBERSECURITY_TIPS))
    return random.sample(CYBERSECURITY_TIPS, sample_size)
