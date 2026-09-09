import crypto from "crypto";

import {
  Redis
} from "@upstash/redis";


const redis =
  Redis.fromEnv();


const OTP_SECRET =
  process.env.OTP_HASH_SECRET;


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


    const otp =
      String(
        req.body?.otp ||
        ""
      )
        .replace(
          /\D/g,
          ""
        );


    if (
      !email ||
      !/^\d{4}$/.test(
        otp
      )
    ) {

      return res
        .status(400)
        .json({
          message:
            "Invalid verification request."
        });

    }



    const key =
      `otp:${email}`;


    const stored =
      await redis.get(
        key
      );


    if (
      !stored
    ) {

      return res
        .status(400)
        .json({

          message:
            "Verification code expired. Please request a new code."

        });

    }



    const record =
      typeof stored ===
      "string"

        ? JSON.parse(
            stored
          )

        : stored;



    if (
      Number(
        record.attempts ||
        0
      ) >= 5
    ) {

      await redis.del(
        key
      );


      return res
        .status(429)
        .json({

          message:
            "Too many incorrect attempts. Please request a new code."

        });

    }



    const submitted =
      crypto
        .createHmac(
          "sha256",
          OTP_SECRET
        )
        .update(
          `${email}:${otp}`
        )
        .digest();



    const expected =
      Buffer.from(
        record.hash,
        "hex"
      );



    const valid =
      expected.length ===
      submitted.length

      &&
      crypto.timingSafeEqual(
        expected,
        submitted
      );



    if (
      !valid
    ) {

      record.attempts =
        Number(
          record.attempts ||
          0
        ) + 1;



      const ttl =
        await redis.ttl(
          key
        );



      if (
        ttl > 0
      ) {

        await redis.set(
          key,
          JSON.stringify(
            record
          ),
          {
            ex: ttl
          }
        );

      }



      return res
        .status(400)
        .json({

          message:
            "Incorrect verification code."

        });

    }



    /*
      OTP becomes unusable
      immediately after success.
    */

    await redis.del(
      key
    );



    return res
      .status(200)
      .json({

        ok: true,

        verified: true,

        email

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
          "Unable to verify code."

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

}
