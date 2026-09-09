
import crypto from "crypto";

import {
  Redis
} from "@upstash/redis";


const redis =
  Redis.fromEnv();


const RESEND_API_KEY =
  process.env.RESEND_API_KEY;


const OTP_SECRET =
  process.env.OTP_HASH_SECRET;


const FROM_EMAIL =
  process.env.FROM_EMAIL;


const ALLOWED_ORIGIN =
  process.env.ALLOWED_ORIGIN;



export default async function handler(
  req,
  res
) {

  setCors(
    req,
    res
  );


  if (
    req.method ===
    "OPTIONS"
  ) {

    return res
      .status(204)
      .end();

  }


  if (
    req.method !==
    "POST"
  ) {

    return res
      .status(405)
      .json({
        message:
          "Method not allowed."
      });

  }


  try {

    const email =
      String(
        req.body?.email ||
        ""
      )
        .trim()
        .toLowerCase();


    if (
      !isValidEmail(
        email
      )
    ) {

      return res
        .status(400)
        .json({
          message:
            "Please enter a valid email address."
        });

    }



    /*
      60 second resend protection
    */

    const cooldownKey =
      `otp:cooldown:${email}`;


    const cooldown =
      await redis.get(
        cooldownKey
      );


    if (
      cooldown
    ) {

      return res
        .status(429)
        .json({
          message:
            "Please wait before requesting another verification code."
        });

    }



    /*
      Secure 4-digit OTP
    */

    const otp =
      crypto
        .randomInt(
          1000,
          10000
        )
        .toString();



    /*
      HMAC the OTP before storage.
      Never store the actual code.
    */

    const hash =
      crypto
        .createHmac(
          "sha256",
          OTP_SECRET
        )
        .update(
          `${email}:${otp}`
        )
        .digest(
          "hex"
        );



    /*
      OTP expires after 10 minutes
    */

    await redis.set(
      `otp:${email}`,
      JSON.stringify({

        hash,

        attempts: 0

      }),
      {
        ex: 600
      }
    );



    await redis.set(
      cooldownKey,
      "1",
      {
        ex: 60
      }
    );



    /*
      Send using Resend
    */

    const response =
      await fetch(
        "https://api.resend.com/emails",
        {

          method:
            "POST",

          headers: {

            Authorization:
              `Bearer ${RESEND_API_KEY}`,

            "Content-Type":
              "application/json"

          },

          body:
            JSON.stringify({

              from:
                FROM_EMAIL,

              to: [
                email
              ],

              subject:
                "Your The Dua Brand verification code",

              html: `

                <div
                  style="
                    max-width:520px;
                    margin:0 auto;
                    padding:40px 24px;
                    font-family:Arial,sans-serif;
                    color:#111;
                  "
                >

                  <h2
                    style="
                      margin:0 0 20px;
                    "
                  >
                    Verify your email
                  </h2>


                  <p>
                    Use the verification
                    code below to continue
                    with The Dua Brand.
                  </p>


                  <div
                    style="
                      margin:30px 0;
                      padding:22px;
                      background:#f4faf7;
                      border-radius:10px;
                      text-align:center;
                    "
                  >

                    <div
                      style="
                        font-size:38px;
                        font-weight:700;
                        letter-spacing:12px;
                        color:#04b778;
                      "
                    >
                      ${otp}
                    </div>

                  </div>


                  <p>
                    This verification code
                    expires in 10 minutes.
                  </p>


                  <p
                    style="
                      margin-top:30px;
                      color:#888;
                      font-size:12px;
                    "
                  >

                    If you did not request
                    this code, you can
                    safely ignore this email.

                  </p>

                </div>

              `

            })

        }
      );



    if (
      !response.ok
    ) {

      console.error(
        await response.text()
      );


      await redis.del(
        `otp:${email}`
      );


      return res
        .status(500)
        .json({
          message:
            "Unable to send verification email."
        });

    }



    return res
      .status(200)
      .json({

        ok: true,

        message:
          "Verification code sent."

      });

  }

  catch (
    error
  ) {

    console.error(
      error
    );


    return res
      .status(500)
      .json({

        message:
          "Unable to send verification code."

      });

  }



  function setCors(
    req,
    res
  ) {

    const origin =
      req.headers.origin;


    if (
      origin ===
      ALLOWED_ORIGIN
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

  }



  function isValidEmail(
    email
  ) {

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      .test(
        email
      );

  }

}
