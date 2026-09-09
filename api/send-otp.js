import crypto from "node:crypto";
import { Redis } from "@upstash/redis";

const redis = Redis.fromEnv();

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const OTP_SECRET = process.env.OTP_HASH_SECRET;
const FROM_EMAIL = process.env.FROM_EMAIL;

const ALLOWED_ORIGINS = new Set([
  "http://localhost:5500",
  "http://127.0.0.1:5500",

  ...String(process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
]);


/* =========================================================
   CORS
========================================================= */

function applyCors(req, res) {
  const origin = req.headers.origin;

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader(
      "Access-Control-Allow-Origin",
      origin
    );
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "POST, OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type"
  );

  res.setHeader(
    "Access-Control-Max-Age",
    "86400"
  );

  res.setHeader(
    "Vary",
    "Origin"
  );

  res.setHeader(
    "Cache-Control",
    "no-store"
  );
}


/* =========================================================
   EMAIL VALIDATION
========================================================= */

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}


/* =========================================================
   REQUEST BODY
========================================================= */

function getBody(req) {
  if (!req.body) {
    return {};
  }

  if (typeof req.body === "string") {
    try {
      return JSON.parse(req.body);
    } catch {
      return {};
    }
  }

  return req.body;
}


/* =========================================================
   API
========================================================= */

export default async function handler(req, res) {
  /*
    IMPORTANT:
    CORS must be applied BEFORE handling OPTIONS.
  */

  applyCors(req, res);


  /* -----------------------------
     Preflight
  ----------------------------- */

  if (req.method === "OPTIONS") {
    return res
      .status(204)
      .end();
  }


  /* -----------------------------
     Only POST
  ----------------------------- */

  if (req.method !== "POST") {
    return res
      .status(405)
      .json({
        message: "Method not allowed."
      });
  }


  try {
    /* -----------------------------
       Environment validation
    ----------------------------- */

    if (
      !RESEND_API_KEY ||
      !OTP_SECRET ||
      !FROM_EMAIL
    ) {
      console.error(
        "Required environment variables are missing."
      );

      return res
        .status(500)
        .json({
          message:
            "Server configuration is incomplete."
        });
    }


    /* -----------------------------
       Read email
    ----------------------------- */

    const body = getBody(req);

    const email = String(
      body.email || ""
    )
      .trim()
      .toLowerCase();


    if (!isValidEmail(email)) {
      return res
        .status(400)
        .json({
          message:
            "Please enter a valid email address."
        });
    }


    /* =====================================================
       RATE LIMIT
       User can request one OTP every 60 seconds
    ===================================================== */

    const cooldownKey =
      `otp:cooldown:${email}`;

    const cooldown =
      await redis.get(cooldownKey);


    if (cooldown) {
      return res
        .status(429)
        .json({
          message:
            "Please wait before requesting another verification code."
        });
    }


    /* =====================================================
       GENERATE SECURE 4-DIGIT OTP
    ===================================================== */

    const otp = crypto
      .randomInt(1000, 10000)
      .toString();


    /* =====================================================
       HASH OTP

       Actual OTP is NOT stored inside Redis.
    ===================================================== */

    const hash = crypto
      .createHmac(
        "sha256",
        OTP_SECRET
      )
      .update(
        `${email}:${otp}`
      )
      .digest("hex");


    /* =====================================================
       STORE OTP

       Expiration: 10 minutes
    ===================================================== */

    const otpKey =
      `otp:${email}`;

    await redis.set(
      otpKey,
      JSON.stringify({
        hash,
        attempts: 0
      }),
      {
        ex: 600
      }
    );


    /* =====================================================
       60 SECOND RESEND COOLDOWN
    ===================================================== */

    await redis.set(
      cooldownKey,
      "1",
      {
        ex: 60
      }
    );


    /* =====================================================
       SEND EMAIL THROUGH RESEND
    ===================================================== */

    const resendResponse =
      await fetch(
        "https://api.resend.com/emails",
        {
          method: "POST",

          headers: {
            Authorization:
              `Bearer ${RESEND_API_KEY}`,

            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({
            from: FROM_EMAIL,

            to: [
              email
            ],

            subject:
              "Your The Dua Brand verification code",

            html: `
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

</head>

<body
  style="
    margin:0;
    padding:0;
    background:#f4faf7;
    font-family:Arial,sans-serif;
    color:#111111;
  "
>

  <div
    style="
      max-width:560px;
      margin:0 auto;
      padding:40px 20px;
    "
  >

    <div
      style="
        background:#ffffff;
        border-radius:16px;
        padding:40px 30px;
        text-align:center;
      "
    >

      <div
        style="
          font-size:13px;
          font-weight:700;
          letter-spacing:2px;
          margin-bottom:25px;
        "
      >
        THE DUA BRAND
      </div>


      <h1
        style="
          margin:0 0 14px;
          font-size:26px;
          line-height:1.2;
        "
      >
        Verify Your Email
      </h1>


      <p
        style="
          margin:0;
          color:#777777;
          font-size:14px;
          line-height:1.6;
        "
      >
        Enter the verification code below
        to continue with The Dua Brand.
      </p>


      <div
        style="
          margin:32px 0;
          padding:24px 15px;
          border-radius:12px;
          background:#eaf9f3;
        "
      >

        <div
          style="
            color:#04b778;
            font-size:40px;
            line-height:1;
            font-weight:700;
            letter-spacing:14px;
            padding-left:14px;
          "
        >
          ${otp}
        </div>

      </div>


      <p
        style="
          margin:0;
          color:#555555;
          font-size:13px;
        "
      >
        This code expires in
        <strong>10 minutes</strong>.
      </p>


      <div
        style="
          height:1px;
          background:#eeeeee;
          margin:30px 0;
        "
      ></div>


      <p
        style="
          margin:0;
          color:#999999;
          font-size:11px;
          line-height:1.5;
        "
      >
        If you did not request this verification
        code, you can safely ignore this email.
      </p>

    </div>

  </div>

</body>

</html>
            `
          })
        }
      );


    /* =====================================================
       RESEND ERROR
    ===================================================== */

    if (!resendResponse.ok) {
      const resendError =
        await resendResponse.text();

      console.error(
        "Resend error:",
        resendError
      );


      /*
        Delete OTP + cooldown if
        email could not be sent.
      */

      await Promise.all([
        redis.del(otpKey),
        redis.del(cooldownKey)
      ]);


      return res
        .status(500)
        .json({
          message:
            "Unable to send verification email."
        });
    }


    /* =====================================================
       SUCCESS
    ===================================================== */

    return res
      .status(200)
      .json({
        ok: true,

        message:
          "Verification code sent."
      });

  } catch (error) {
    console.error(
      "send-otp error:",
      error
    );


    return res
      .status(500)
      .json({
        message:
          "Unable to send verification code."
      });
  }
}
