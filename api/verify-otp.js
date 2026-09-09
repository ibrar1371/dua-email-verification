import crypto from "node:crypto";
import { Redis } from "@upstash/redis";

const redis = Redis.fromEnv();

const OTP_SECRET =
  process.env.OTP_HASH_SECRET;

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
  const origin =
    req.headers.origin;

  if (
    origin &&
    ALLOWED_ORIGINS.has(origin)
  ) {
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

  if (
    typeof req.body === "string"
  ) {
    try {
      return JSON.parse(
        req.body
      );
    } catch {
      return {};
    }
  }

  return req.body;
}


/* =========================================================
   API
========================================================= */

export default async function handler(
  req,
  res
) {
  /*
    Must happen before OPTIONS response.
  */

  applyCors(req, res);


  /* -----------------------------
     CORS preflight
  ----------------------------- */

  if (
    req.method === "OPTIONS"
  ) {
    return res
      .status(204)
      .end();
  }


  /* -----------------------------
     POST only
  ----------------------------- */

  if (
    req.method !== "POST"
  ) {
    return res
      .status(405)
      .json({
        message:
          "Method not allowed."
      });
  }


  try {
    if (!OTP_SECRET) {
      console.error(
        "OTP_HASH_SECRET is missing."
      );

      return res
        .status(500)
        .json({
          message:
            "Server configuration is incomplete."
        });
    }


    const body =
      getBody(req);


    const email = String(
      body.email || ""
    )
      .trim()
      .toLowerCase();


    const otp = String(
      body.otp || ""
    )
      .replace(
        /\D/g,
        ""
      );


    /* =====================================================
       VALIDATE REQUEST
    ===================================================== */

    if (
      !isValidEmail(email) ||
      !/^\d{4}$/.test(otp)
    ) {
      return res
        .status(400)
        .json({
          message:
            "Invalid verification request."
        });
    }


    /* =====================================================
       GET OTP
    ===================================================== */

    const key =
      `otp:${email}`;


    const stored =
      await redis.get(key);


    if (!stored) {
      return res
        .status(400)
        .json({
          message:
            "Verification code expired. Please request a new code."
        });
    }


    /* =====================================================
       PARSE REDIS RECORD
    ===================================================== */

    let record;


    try {
      record =
        typeof stored === "string"
          ? JSON.parse(stored)
          : stored;
    } catch {
      await redis.del(key);

      return res
        .status(400)
        .json({
          message:
            "Verification code is no longer valid."
        });
    }


    if (
      !record ||
      !record.hash
    ) {
      await redis.del(key);

      return res
        .status(400)
        .json({
          message:
            "Verification code is no longer valid."
        });
    }


    /* =====================================================
       MAX ATTEMPTS
    ===================================================== */

    const attempts =
      Number(
        record.attempts || 0
      );


    if (
      attempts >= 5
    ) {
      await redis.del(key);

      return res
        .status(429)
        .json({
          message:
            "Too many incorrect attempts. Please request a new code."
        });
    }


    /* =====================================================
       HASH SUBMITTED OTP
    ===================================================== */

    const submittedHash =
      crypto
        .createHmac(
          "sha256",
          OTP_SECRET
        )
        .update(
          `${email}:${otp}`
        )
        .digest();


    let expectedHash;


    try {
      expectedHash =
        Buffer.from(
          record.hash,
          "hex"
        );
    } catch {
      await redis.del(key);

      return res
        .status(400)
        .json({
          message:
            "Verification code is no longer valid."
        });
    }


    /* =====================================================
       TIMING SAFE COMPARISON
    ===================================================== */

    const valid =
      expectedHash.length ===
        submittedHash.length &&

      crypto.timingSafeEqual(
        expectedHash,
        submittedHash
      );


    /* =====================================================
       INCORRECT OTP
    ===================================================== */

    if (!valid) {
      record.attempts =
        attempts + 1;


      const remainingTtl =
        await redis.ttl(key);


      /*
        If OTP has already expired,
        remove it.
      */

      if (
        remainingTtl <= 0
      ) {
        await redis.del(key);

        return res
          .status(400)
          .json({
            message:
              "Verification code expired. Please request a new code."
          });
      }


      /*
        Preserve original remaining TTL.
      */

      await redis.set(
        key,
        JSON.stringify(record),
        {
          ex: remainingTtl
        }
      );


      const attemptsLeft =
        Math.max(
          0,
          5 - record.attempts
        );


      return res
        .status(400)
        .json({
          message:
            attemptsLeft > 0
              ? `Incorrect verification code. ${attemptsLeft} attempt${attemptsLeft === 1 ? "" : "s"} remaining.`
              : "Too many incorrect attempts. Please request a new code."
        });
    }


    /* =====================================================
       SUCCESS

       OTP is single-use.
    ===================================================== */

    await redis.del(key);


    return res
      .status(200)
      .json({
        ok: true,

        verified: true,

        email
      });

  } catch (error) {
    console.error(
      "verify-otp error:",
      error
    );


    return res
      .status(500)
      .json({
        message:
          "Unable to verify code."
      });
  }
}
