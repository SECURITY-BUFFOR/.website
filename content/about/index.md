---
title: About
toc: false
layout: hextra-home
---
<style>
    .profile-container {
        display: flex;
        flex-direction: row; 
        align-items: center; 
        max-width: 900px; 
        padding: 20px;
        box-sizing: border-box; 
        border-radius: 10px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        margin: 20px 0; 
    }

    .profile-image {
        width: 200px; 
        height: 200px; 
        object-fit: cover;
        border-radius: 50%; 
        margin-right: 40px;
        flex-shrink: 0; 
    }

    .profile-text {
        flex-grow: 1; 
    }

    .profile-text h1 {
        margin: 0 0 10px 0;
        font-size: 2.5em; 
    }

    .profile-text p {
        margin: 0;
        line-height: 1.6;
        font-size: 1.1em;
    }

    /* --- Timeline Styles --- */
    .timeline {
        border-left: 3px solid rgba(254, 97, 97, 0.5);
        margin: 40px 0 40px 20px;
        padding-left: 30px;
        position: relative;
    }

    .timeline-item {
        position: relative;
        margin-bottom: 30px;
    }

    .timeline-item:last-child {
        margin-bottom: 0;
    }

    .timeline-dot {
        position: absolute;
        left: -38.5px;
        top: 5px;
        width: 14px;
        height: 14px;
        background-color: #fe6161;
        border-radius: 50%;
        box-shadow: 0 0 0 4px rgba(254, 97, 97, 0.2);
    }

    .timeline-date {
        font-weight: 600;
        color: #fe6161;
        margin-bottom: 5px;
        font-size: 0.95em;
        letter-spacing: 0.5px;
    }

    .timeline-content h3 {
        margin: 0 0 5px 0;
        font-size: 1.3em;
    }

    .timeline-content h4 {
        margin: 0 0 10px 0;
        font-size: 1em;
        font-weight: normal;
        opacity: 0.8;
    }

    .timeline-content p {
        margin: 0;
        line-height: 1.5;
        font-size: 0.95em;
        opacity: 0.9;
    }

    /* --- Media Queries for Responsiveness --- */
    @media (max-width: 768px) {
        .profile-container {
            flex-direction: column; 
            text-align: center; 
            margin: 20px auto;
        }

        .profile-image {
            width: 150px; 
            height: 150px;
            margin-right: 0; 
            margin-bottom: 20px; 
        }

        .profile-text h1 {
            font-size: 2em;
        }

        .profile-text p {
            font-size: 1em;
        }
        
        .timeline {
            margin-left: 10px;
        }
    }

    @media (max-width: 480px) {
        .profile-container {
            padding: 15px;
        }

        .profile-image {
            width: 120px; 
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
  $WHOAMI
{{< /hextra/hero-headline >}}

<div class="profile-container">
    <img src="/images/jellylogo.png" alt="Jellyfish Logo" class="profile-image" />
    <div class="profile-text">
        <h1>Hi, I'm Krzysztof Greś (h4mr3r)</h1>
        <p>I'm a Senior Red Team Specialist @ Netia and malware developer.</p>
    </div>
</div>


<h2>Certificates</h2>

{{< cards >}}
  {{< card
        link="/images/certs/crt_CRTP.png"
        title="Altered Security - Certified Red Team Professional (CRTP)"
        image="/images/certs/crt_CRTP.png"
        imageStyle="object-fit:cover; aspect-ratio:16/9;"
  >}}

  {{< card
        link="/images/certs/crt_CPTS.jpeg"
        title="HackTheBox - Certified Penetration Testing Specialist (CPTS)"
        image="/images/certs/crt_CPTS.jpeg"
        imageStyle="object-fit:cover; aspect-ratio:16/9;"
  >}}
{{< /cards >}}

<br /><br />


<h2>Career Path</h2>
<div class="timeline">
    <div class="timeline-item">
        <div class="timeline-dot"></div>
        <div class="timeline-date">Oct 2025 - Present</div>
        <div class="timeline-content">
            <h3>Senior Red Team Specialist</h3>
            <h4>Netia</h4>
        </div>
    </div>
    <div class="timeline-item">
        <div class="timeline-dot"></div>
        <div class="timeline-date">Oct 2024 - Oct 2025</div>
        <div class="timeline-content">
            <h3>Senior Cyber Security Consultant</h3>
            <h4>KPMG Poland</h4>
        </div>
    </div>
    <div class="timeline-item">
        <div class="timeline-dot"></div>
        <div class="timeline-date">Apr 2023 - Oct 2024</div>
        <div class="timeline-content">
            <h3>Cyber Security Consultant</h3>
            <h4>KPMG Poland</h4>
        </div>
    </div>
    <div class="timeline-item">
        <div class="timeline-dot"></div>
        <div class="timeline-date">Jan 2022 - Apr 2023</div>
        <div class="timeline-content">
            <h3>Cyber Security Junior Consultant</h3>
            <h4>KPMG Poland</h4>
        </div>
    </div>
    <div class="timeline-item">
        <div class="timeline-dot"></div>
        <div class="timeline-date">Jul 2021 - Jan 2022</div>
        <div class="timeline-content">
            <h3>Cyber Security Intern</h3>
            <h4>KPMG Poland</h4>
        </div>
    </div>
</div>


<p style="margin: 0; line-height: 1.6;">
    Want to reach out? 
</p>

{{< hextra/feature-grid >}}
  {{< hextra/feature-card
    title="LinkedIn"
    subtitle="Visit my LinkedIn profile"
    link="https://www.linkedin.com/in/kgres/"
    style="background: radial-gradient(ellipse at 50% 80%,rgba(10, 102, 194, 0.15),hsla(0,0%,100%,0));"

  >}}
  {{< hextra/feature-card
    title="E-Mail"
    subtitle="Write me: h4mr3r\@securitybuffor.com"
    link="mailto:h4mr3r@securitybuffor.com"
    style="background: radial-gradient(ellipse at 50% 80%,rgba(99, 102, 241, 0.15),hsla(0,0%,100%,0));"
  >}}
{{< /hextra/feature-grid >}}