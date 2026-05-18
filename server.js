require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(
  express.json({
    limit: "2mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  })
);
app.use(cors());

const ZWITCH_BASE_URL = process.env.ZWITCH_BASE_URL || "https://api.zwitch.io";

function getZwitchConfig() {
  return {
    baseUrl: ZWITCH_BASE_URL.replace(/\/$/, ""),
    env: process.env.ZWITCH_ENV || "sandbox",
    accessKey: process.env.ZWITCH_ACCESS_KEY,
    secretKey: process.env.ZWITCH_SECRET_KEY,
    accountId: process.env.ZWITCH_ACCOUNT_ID,
    webhookSecret: process.env.ZWITCH_WEBHOOK_SECRET,
  };
}

function requireZwitchKeys() {
  const config = getZwitchConfig();

  if (!config.accessKey || !config.secretKey) {
    const error = new Error("Missing ZWITCH_ACCESS_KEY or ZWITCH_SECRET_KEY");
    error.statusCode = 500;
    throw error;
  }

  return config;
}

function zwitchHeaders(config) {
  return {
    Accept: "application/json",
    "Content-Type": "application/json",
    Authorization: `Bearer ${config.accessKey}:${config.secretKey}`,
  };
}

async function callZwitch(method, path, { data, params } = {}) {
  const config = requireZwitchKeys();
  const response = await axios({
    method,
    url: `${config.baseUrl}${path}`,
    data,
    params,
    headers: zwitchHeaders(config),
    timeout: 30000,
    validateStatus: () => true,
  });

  if (response.status >= 400) {
    const error = new Error("Zwitch API request failed");
    error.statusCode = response.status;
    error.details = response.data;
    throw error;
  }

  return response.data;
}

function asyncHandler(handler) {
  return async (req, res, next) => {
    try {
      await handler(req, res);
    } catch (error) {
      next(error);
    }
  };
}

function requiredFields(body, fields) {
  return fields.filter((field) => body[field] === undefined || body[field] === null || body[field] === "");
}

function cleanReferenceId(value, fallbackPrefix = "REF") {
  const cleaned = String(value || `${fallbackPrefix}${Date.now()}`).replace(/[^a-zA-Z0-9]/g, "");
  return cleaned.slice(0, 40);
}

function normalizeIfsc(value) {
  return String(value || "").trim().toUpperCase();
}

function getAccountId(body = {}) {
  return body.debit_account_id || body.account_id || body.accountId || getZwitchConfig().accountId;
}

function buildWebhookSignature(secret, payload) {
  const prehash = JSON.stringify(payload);
  return crypto.createHmac("sha256", secret).update(prehash).digest("hex");
}

function isValidWebhookSignature(req) {
  const { webhookSecret } = getZwitchConfig();

  if (!webhookSecret) {
    return { valid: true, checked: false };
  }

  const receivedSignature = req.get("x-zwitch-signature");
  if (!receivedSignature) {
    return { valid: false, checked: true };
  }

  const computedSignature = buildWebhookSignature(webhookSecret, req.body || {});

  try {
    return {
      valid: crypto.timingSafeEqual(Buffer.from(computedSignature), Buffer.from(receivedSignature)),
      checked: true,
    };
  } catch (_error) {
    return { valid: false, checked: true };
  }
}

app.get("/health", (_req, res) => {
  const config = getZwitchConfig();

  res.json({
    success: true,
    service: "zwitch-render-express-api",
    mode: config.env,
    zwitch_base_url: config.baseUrl,
    sandbox_note: "Use sandbox API keys from the Zwitch dashboard with https://api.zwitch.io.",
    has_access_key: Boolean(config.accessKey),
    has_secret_key: Boolean(config.secretKey),
    has_default_account_id: Boolean(config.accountId),
    has_webhook_secret: Boolean(config.webhookSecret),
  });
});

app.post(
  "/beneficiaries",
  asyncHandler(async (req, res) => {
    const accountId = getAccountId(req.body);
    const missing = requiredFields(req.body, [
      "name_of_account_holder",
      "bank_account_number",
      "bank_ifsc_code",
    ]);

    if (!accountId) {
      missing.push("account_id or ZWITCH_ACCOUNT_ID");
    }

    if (missing.length) {
      return res.status(400).json({ success: false, message: "Missing required fields", missing });
    }

    const payload = {
      type: "account_number",
      name_of_account_holder: req.body.name_of_account_holder,
      email: req.body.email,
      phone: req.body.phone,
      bank_account_number: String(req.body.bank_account_number).trim(),
      bank_ifsc_code: normalizeIfsc(req.body.bank_ifsc_code),
      bank_name: req.body.bank_name,
      metadata: req.body.metadata,
    };

    const data = await callZwitch("post", `/v1/accounts/${accountId}/beneficiaries`, { data: payload });

    res.status(201).json({
      success: true,
      message: "Beneficiary created",
      data,
    });
  })
);

app.get(
  "/beneficiaries/:beneficiaryId",
  asyncHandler(async (req, res) => {
    const data = await callZwitch("get", `/v1/accounts/beneficiaries/${req.params.beneficiaryId}`);

    res.json({
      success: true,
      message: "Beneficiary fetched",
      data,
    });
  })
);

app.post(
  "/verifications/bank-account",
  asyncHandler(async (req, res) => {
    const missing = requiredFields(req.body, [
      "bank_account_number",
      "bank_ifsc_code",
      "merchant_reference_id",
    ]);

    if (missing.length) {
      return res.status(400).json({ success: false, message: "Missing required fields", missing });
    }

    const payload = {
      bank_account_number: String(req.body.bank_account_number).trim(),
      bank_ifsc_code: normalizeIfsc(req.body.bank_ifsc_code),
      force_penny_drop: Boolean(req.body.force_penny_drop),
      merchant_reference_id: cleanReferenceId(req.body.merchant_reference_id, "BANK"),
      metadata: req.body.metadata,
    };

    if (req.body.force_penny_drop_amount !== undefined) {
      payload.force_penny_drop_amount = Number(req.body.force_penny_drop_amount);
    }

    const data = await callZwitch("post", "/v1/verifications/bank-account", { data: payload });

    res.json({
      success: true,
      message: "Bank account verification request completed",
      data,
    });
  })
);

app.post(
  "/kyc/pan",
  asyncHandler(async (req, res) => {
    const missing = requiredFields(req.body, ["pan", "merchant_reference_id"]);

    if (missing.length) {
      return res.status(400).json({ success: false, message: "Missing required fields", missing });
    }

    const payload = {
      pan: String(req.body.pan).trim().toUpperCase(),
      consent: true,
      merchant_reference_id: cleanReferenceId(req.body.merchant_reference_id, "PAN"),
      metadata: req.body.metadata,
    };

    const data = await callZwitch("post", "/v1/kycs/pan", { data: payload });

    res.json({
      success: true,
      message: "PAN KYC verification request completed",
      data,
    });
  })
);

app.post(
  "/transfers",
  asyncHandler(async (req, res) => {
    const accountId = getAccountId(req.body);
    const missing = requiredFields(req.body, [
      "beneficiary_id",
      "amount",
      "merchant_reference_id",
      "payment_mode",
    ]);

    if (!accountId) {
      missing.push("debit_account_id or ZWITCH_ACCOUNT_ID");
    }

    if (missing.length) {
      return res.status(400).json({ success: false, message: "Missing required fields", missing });
    }

    const payload = {
      type: "account_number",
      debit_account_id: accountId,
      beneficiary_id: req.body.beneficiary_id,
      amount: Number(req.body.amount),
      currency_code: req.body.currency_code || "inr",
      payment_mode: req.body.payment_mode,
      async: Boolean(req.body.async),
      merchant_reference_id: cleanReferenceId(req.body.merchant_reference_id, "TR"),
      payment_remark: req.body.payment_remark,
      metadata: req.body.metadata,
    };

    const data = await callZwitch("post", "/v1/transfers", { data: payload });

    res.status(201).json({
      success: true,
      message: "Transfer created",
      data,
    });
  })
);

app.get(
  "/transfers/:transferId",
  asyncHandler(async (req, res) => {
    const data = await callZwitch("get", `/v1/transfers/${req.params.transferId}`);

    res.json({
      success: true,
      message: "Transfer fetched",
      data,
    });
  })
);

app.get(
  "/transfers",
  asyncHandler(async (req, res) => {
    const allowedQueryParams = [
      "results_per_page",
      "start_before",
      "start_after",
      "from_date",
      "to_date",
      "debit_account_id",
      "credit_account_id",
      "beneficiary_id",
      "merchant_reference_id",
      "bulk_reference_id",
    ];

    const params = {};
    for (const key of allowedQueryParams) {
      if (req.query[key] !== undefined) {
        params[key] = req.query[key];
      }
    }

    const data = await callZwitch("get", "/v1/transfers", { params });

    res.json({
      success: true,
      message: "Transfers fetched",
      data,
    });
  })
);

app.post(
  "/transfers/bulk",
  asyncHandler(async (req, res) => {
    const accountId = getAccountId(req.body);
    const missing = requiredFields(req.body, ["bulk_reference_id", "transfers"]);

    if (!accountId) {
      missing.push("debit_account_id or ZWITCH_ACCOUNT_ID");
    }

    if (!Array.isArray(req.body.transfers) || req.body.transfers.length === 0) {
      missing.push("transfers must be a non-empty array");
    }

    if (missing.length) {
      return res.status(400).json({ success: false, message: "Missing required fields", missing });
    }

    const payload = {
      type: "account_number",
      debit_account_id: accountId,
      bulk_reference_id: cleanReferenceId(req.body.bulk_reference_id, "BULK"),
      transfers: req.body.transfers.map((transfer) => ({
        beneficiary_id: transfer.beneficiary_id,
        amount: Number(transfer.amount),
        currency_code: transfer.currency_code || "inr",
        payment_mode: transfer.payment_mode,
        merchant_reference_id: cleanReferenceId(transfer.merchant_reference_id, "TR"),
        payment_remark: transfer.payment_remark,
        metadata: transfer.metadata,
      })),
    };

    const data = await callZwitch("post", "/v2/transfers/bulk", { data: payload });

    res.status(201).json({
      success: true,
      message: "Bulk transfer created",
      data,
    });
  })
);

app.get(
  "/transfers/bulk/:bulkTransferId",
  asyncHandler(async (req, res) => {
    const data = await callZwitch("get", `/v2/transfers/bulk/${req.params.bulkTransferId}`);

    res.json({
      success: true,
      message: "Bulk transfer fetched",
      data,
    });
  })
);

app.post(
  "/sandbox/accounts/:accountId/test-balance",
  asyncHandler(async (req, res) => {
    const missing = requiredFields(req.body, ["amount"]);

    if (missing.length) {
      return res.status(400).json({ success: false, message: "Missing required fields", missing });
    }

    const data = await callZwitch("post", `/v1/accounts/${req.params.accountId}/test-balance`, {
      data: { amount: Number(req.body.amount) },
    });

    res.json({
      success: true,
      message: "Sandbox test balance added",
      data,
    });
  })
);

app.post("/webhook/zwitch", (req, res) => {
  const signatureResult = isValidWebhookSignature(req);

  if (!signatureResult.valid) {
    return res.status(401).json({
      success: false,
      message: "Invalid Zwitch webhook signature",
    });
  }

  const event = req.body || {};
  const resource = event.data && event.data.object ? event.data.object : event.data;

  console.log("Zwitch webhook received", {
    event_id: event.id,
    event_name: event.name,
    object_id: resource && resource.id,
    status: resource && resource.status,
    signature_checked: signatureResult.checked,
  });

  res.json({
    success: true,
    received: true,
    message: "Webhook received",
    event_name: event.name || null,
    event_id: event.id || null,
    signature_checked: signatureResult.checked,
  });
});

///----------------------- Add verification money testing not needed in live
app.post(
  "/sandbox/verification-account/test-balance",
  asyncHandler(async (req, res) => {
    const verificationAccountId =
      req.body.account_id ||
      process.env.ZWITCH_VERIFICATION_ACCOUNT_ID;

    const missing = requiredFields(req.body, ["amount"]);

    if (!verificationAccountId) {
      missing.push("account_id or ZWITCH_VERIFICATION_ACCOUNT_ID");
    }

    if (missing.length) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields",
        missing,
      });
    }

    const data = await callZwitch(
      "post",
      `/v1/accounts/${verificationAccountId}/test-balance`,
      {
        data: {
          amount: Number(req.body.amount),
        },
      }
    );

    res.json({
      success: true,
      message: "Sandbox verification account test balance added",
      data,
    });
  })
);

app.post(
  "/verifications/bank-account/pennyless",
  asyncHandler(async (req, res) => {
    const missing = requiredFields(req.body, [
      "bank_account_number",
      "bank_ifsc_code",
    ]);

    if (missing.length) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields",
        missing,
      });
    }

    const merchantReferenceId =
      req.body.merchant_reference_id ||
      `BANKPENNYLESS${Date.now()}${Math.floor(Math.random() * 10000)}`;

    const payload = {
      bank_account_number: String(req.body.bank_account_number).trim(),
      bank_ifsc_code: normalizeIfsc(req.body.bank_ifsc_code),
      merchant_reference_id: cleanReferenceId(merchantReferenceId, "BANKPENNYLESS"),
      metadata: req.body.metadata,
    };

    const data = await callZwitch(
      "post",
      "/v1/kycs/verifications/bank-account/pennyless",
      { data: payload }
    );

    res.json({
      success: true,
      message: "Pennyless bank account verification completed",
      merchant_reference_id: payload.merchant_reference_id,
      data,
    });
  })
);
///----------------------------------------------------
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
    method: req.method,
    path: req.originalUrl,
  });
});

app.use((error, _req, res, _next) => {
  const statusCode = error.statusCode || 500;

  console.error("API error", {
    message: error.message,
    statusCode,
    details: error.details,
  });

  res.status(statusCode).json({
    success: false,
    message: error.message || "Internal server error",
    error: error.details || null,
  });
});

app.listen(PORT, () => {
  console.log(`Zwitch Express API listening on port ${PORT}`);
});
///