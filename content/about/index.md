---
title: About
toc: false
layout: hextra-home
---
<style>
    .profile-container {
    display: flex;
    flex-direction: row; /* Default for larger screens: image and text side-by-side */
    align-items: center; /* Vertically align items in the center */
    max-width: 900px; /* Limit overall width for desktop view */
    padding: 20px;
    box-sizing: border-box; /* Include padding in element's total width and height */
    border-radius: 10px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    margin: 20px; /* Add some margin for smaller screens to prevent sticking to edges */
}

.profile-image {
    width: 200px; /* Fixed width for desktop, will be fluid on mobile */
    height: 200px; /* Fixed height for desktop */
    object-fit: cover;
    border-radius: 50%; /* Makes it perfectly circular */
    margin-right: 40px;
    flex-shrink: 0; /* Prevents the image from shrinking initially */
}

.profile-text {
    flex-grow: 1; /* Allows text to take up available space */
}

.profile-text h1 {
    margin: 0 0 10px 0;
    font-size: 2.5em; /* Adjust font size relative to parent font size */
}

.profile-text p {
    margin: 0;
    line-height: 1.6;
    font-size: 1.1em;
}

/* --- Media Queries for Responsiveness --- */

/* For screens smaller than 768px (e.g., tablets and smaller) */
@media (max-width: 768px) {
    .profile-container {
        flex-direction: column; /* Stack image and text vertically */
        text-align: center; /* Center align text */
    }

    .profile-image {
        width: 150px; /* Slightly smaller image on tablets */
        height: 150px;
        margin-right: 0; /* Remove right margin */
        margin-bottom: 20px; /* Add space below the image */
    }

    .profile-text h1 {
        font-size: 2em;
    }

    .profile-text p {
        font-size: 1em;
    }
}

/* For screens smaller than 480px (e.g., mobile phones) */
@media (max-width: 480px) {
    .profile-container {
        padding: 15px;
        margin: 15px;
    }

    .profile-image {
        width: 120px; /* Even smaller image on mobile */
        height: 120px;
        margin-bottom: 15px;
    }

    .profile-text h1 {
        font-size: 1.8em;
    }

    .profile-text p {
        font-size: 0.9em;
    }
}

</style>
<br />
{{< hextra/hero-headline >}}
  \$WHOAMI
{{< /hextra/hero-headline >}}

<div class="profile-container">
    <img src="/images/jellylogo.png" alt="Jellyfish Logo" class="profile-image" />

<div class="profile-text">
    <h1>Hi, I'm h4mr3r</h1>
    <p>I'm malware developer @ KPMG and Red Team operator.</p>
</div>
</div>
<br /><br /><br />
    <p style="margin: 0; line-height: 1.6;">
    Want to reach out? 
    </p>


{{< hextra/feature-grid >}}
  {{< hextra/feature-card
    title="LinkedIn"
    subtitle="Visit my LinkedIn profile"
    link="https://www.linkedin.com/in/kgres/"
    style="background: radial-gradient(ellipse at 50% 80%,rgba(254, 97, 97, 0.15),hsla(0,0%,100%,0)); display:flex;"
  >}}
    {{< hextra/feature-card
    title="E-Mail"
    subtitle="Write me: h4mr3r\@securitybuffor.com"
    link="mailto:h4mr3r@securitybuffor.com"
    style="background: radial-gradient(ellipse at 50% 80%,rgba(254, 97, 97, 0.15),hsla(0,0%,100%,0)); display:flex;"
  >}}
  
{{< /hextra/feature-grid >}}

