const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "come-by-change-this-secret";

app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

/*
  COME BY
  #TlaKwana

  V3 core:
  - Client requests
  - Provider availability
  - Provider interest
  - Accepted matches
  - Live location
  - Private messaging
  - History
*/

const upload = multer({
  storage: multer.memoryStorage(),

  limits: {
    files: 3,
    fileSize: 4 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    cb(null, allowed.includes(file.mimetype));
  }
});

async function initDatabase() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,

      name VARCHAR(120) NOT NULL,

      phone VARCHAR(40) UNIQUE NOT NULL,

      role VARCHAR(20) NOT NULL
        CHECK(role IN ('client','provider')),

      password_hash TEXT NOT NULL,

      age INTEGER,

      photos TEXT[] DEFAULT '{}',

      available BOOLEAN DEFAULT FALSE,

      location_enabled BOOLEAN DEFAULT FALSE,

      latitude DOUBLE PRECISION,

      longitude DOUBLE PRECISION,

      location_updated_at TIMESTAMP,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS age INTEGER
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS photos TEXT[] DEFAULT '{}'
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS available BOOLEAN DEFAULT FALSE
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS location_enabled BOOLEAN DEFAULT FALSE
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS location_updated_at TIMESTAMP
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS requests (
      id SERIAL PRIMARY KEY,

      client_id INTEGER
        REFERENCES users(id)
        ON DELETE CASCADE,

      assistance_type VARCHAR(20) NOT NULL
        CHECK(
          assistance_type IN
          ('SHORT TIME','SLEEP OVER')
        ),

      transport_type VARCHAR(20) NOT NULL
        CHECK(
          transport_type IN
          ('PICK & DROP','DRIVE THROUGH')
        ),

      area VARCHAR(200) NOT NULL,

      amount NUMERIC(12,2),

      details TEXT,

      latitude DOUBLE PRECISION,

      longitude DOUBLE PRECISION,

      status VARCHAR(30) DEFAULT 'OPEN',

      accepted_provider_id INTEGER
        REFERENCES users(id),

      started_at TIMESTAMP,

      completed_at TIMESTAMP,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS interests (
      id SERIAL PRIMARY KEY,

      request_id INTEGER
        REFERENCES requests(id)
        ON DELETE CASCADE,

      provider_id INTEGER
        REFERENCES users(id)
        ON DELETE CASCADE,

      location_enabled BOOLEAN DEFAULT FALSE,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      UNIQUE(request_id, provider_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,

      request_id INTEGER
        REFERENCES requests(id)
        ON DELETE CASCADE,

      sender_id INTEGER
        REFERENCES users(id)
        ON DELETE CASCADE,

      receiver_id INTEGER
        REFERENCES users(id)
        ON DELETE CASCADE,

      body TEXT NOT NULL,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS location_sessions (
      id SERIAL PRIMARY KEY,

      request_id INTEGER
        REFERENCES requests(id)
        ON DELETE CASCADE,

      provider_id INTEGER
        REFERENCES users(id)
        ON DELETE CASCADE,

      active BOOLEAN DEFAULT TRUE,

      started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      ended_at TIMESTAMP
    )
  `);

  console.log("COME BY database ready");
}

function authenticate(req, res, next) {

  try {

    const header =
      req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required."
      });
    }

    const token =
      header.substring(7);

    req.user =
      jwt.verify(token, JWT_SECRET);

    next();

  } catch (error) {

    return res.status(401).json({
      error: "Invalid or expired session."
    });
  }
}

function createToken(user) {

  return jwt.sign(
    {
      id: user.id,
      role: user.role
    },

    JWT_SECRET,

    {
      expiresIn: "30d"
    }
  );
}

function cleanUser(user) {

  return {
    id: user.id,
    name: user.name,
    phone: user.phone,
    role: user.role,
    age: user.age,
    photos: user.photos || [],
    available: !!user.available,
    location_enabled: !!user.location_enabled
  };
  }
// ================================
// AUTHENTICATION
// ================================

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      phone,
      password,
      role
    } = req.body;

    if (
      !name ||
      !phone ||
      !password ||
      !["client", "provider"].includes(role)
    ) {
      return res.status(400).json({
        error: "Please complete all registration fields."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must contain at least 6 characters."
      });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE phone = $1",
      [phone]
    );

    if (existing.rowCount) {
      return res.status(409).json({
        error: "An account with this phone number already exists."
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (
        name,
        phone,
        role,
        password_hash
      )
      VALUES
      ($1,$2,$3,$4)

      RETURNING
        id,
        name,
        phone,
        role,
        age,
        photos,
        available,
        location_enabled
      `,
      [
        name.trim(),
        phone.trim(),
        role,
        passwordHash
      ]
    );

    const user = result.rows[0];

    res.status(201).json({
      token: createToken(user),
      user: cleanUser(user)
    });

  } catch (error) {

    console.error(
      "REGISTER ERROR:",
      error
    );

    res.status(500).json({
      error: "Unable to create account."
    });
  }
});


// ================================
// LOGIN
// ================================

app.post("/api/auth/login", async (req, res) => {

  try {

    const {
      phone,
      password
    } = req.body;

    if (!phone || !password) {

      return res.status(400).json({
        error: "Phone number and password are required."
      });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE phone = $1",
      [phone.trim()]
    );

    if (!result.rowCount) {

      return res.status(401).json({
        error: "Invalid phone number or password."
      });
    }

    const user = result.rows[0];

    const valid =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!valid) {

      return res.status(401).json({
        error: "Invalid phone number or password."
      });
    }

    res.json({
      token: createToken(user),
      user: cleanUser(user)
    });

  } catch (error) {

    console.error(
      "LOGIN ERROR:",
      error
    );

    res.status(500).json({
      error: "Unable to log in."
    });
  }
});


// ================================
// CURRENT USER
// ================================

app.get(
  "/api/auth/me",
  authenticate,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT
          id,
          name,
          phone,
          role,
          age,
          photos,
          available,
          location_enabled
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

      if (!result.rowCount) {

        return res.status(401).json({
          error: "User account not found."
        });
      }

      res.json({
        user: cleanUser(result.rows[0])
      });

    } catch (error) {

      res.status(500).json({
        error: "Unable to load profile."
      });
    }
  }
);


// ================================
// UPDATE PROFILE
// ================================

app.put(
  "/api/profile",
  authenticate,
  async (req, res) => {

    try {

      const age =
        req.body.age == null ||
        req.body.age === ""
          ? null
          : Number(req.body.age);

      if (
        age !== null &&
        (
          !Number.isInteger(age) ||
          age < 18 ||
          age > 100
        )
      ) {

        return res.status(400).json({
          error: "Age must be between 18 and 100."
        });
      }

      const result = await pool.query(
        `
        UPDATE users
        SET age = $1
        WHERE id = $2

        RETURNING
          id,
          name,
          phone,
          role,
          age,
          photos,
          available,
          location_enabled
        `,
        [
          age,
          req.user.id
        ]
      );

      res.json({
        user: cleanUser(result.rows[0])
      });

    } catch (error) {

      console.error(
        "PROFILE ERROR:",
        error
      );

      res.status(500).json({
        error: "Unable to update profile."
      });
    }
  }
);


// ================================
// PROVIDER AVAILABILITY
// ================================

app.put(
  "/api/provider/availability",
  authenticate,
  async (req, res) => {

    try {

      if (req.user.role !== "provider") {

        return res.status(403).json({
          error:
            "Only service providers can change availability."
        });
      }

      const available =
        Boolean(req.body.available);

      const result = await pool.query(
        `
        UPDATE users
        SET available = $1
        WHERE id = $2

        RETURNING
          id,
          name,
          phone,
          role,
          age,
          photos,
          available,
          location_enabled
        `,
        [
          available,
          req.user.id
        ]
      );

      res.json({
        message:
          available
            ? "You are now AVAILABLE for requests."
            : "You are now UNAVAILABLE for requests.",

        user: cleanUser(result.rows[0])
      });

    } catch (error) {

      console.error(
        "AVAILABILITY ERROR:",
        error
      );

      res.status(500).json({
        error: "Unable to update availability."
      });
    }
  }
);


// ================================
// PROVIDER PHOTOS
// ================================

app.post(
  "/api/profile/photos",
  authenticate,
  upload.array("photos", 3),

  async (req, res) => {

    try {

      if (req.user.role !== "provider") {

        return res.status(403).json({
          error:
            "Only service providers can upload profile photos."
        });
      }

      const files =
        req.files || [];

      if (
        files.length < 1 ||
        files.length > 3
      ) {

        return res.status(400).json({
          error:
            "Please select between 1 and 3 photos."
        });
      }

      const photos =
        files.map(file =>
          `data:${file.mimetype};base64,${file.buffer.toString("base64")}`
        );

      const result = await pool.query(
        `
        UPDATE users
        SET photos = $1
        WHERE id = $2

        RETURNING
          id,
          name,
          phone,
          role,
          age,
          photos,
          available,
          location_enabled
        `,
        [
          photos,
          req.user.id
        ]
      );

      res.json({
        message:
          "Provider photos updated.",

        user:
          cleanUser(result.rows[0])
      });

    } catch (error) {

      console.error(
        "PHOTO ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to upload profile photos."
      });
    }
  }
);


// ================================
// AVAILABLE PROVIDERS
// ================================

app.get(
  "/api/providers/available",
  authenticate,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT
          id,
          name,
          age,
          photos,
          available,
          location_enabled,
          latitude,
          longitude,
          location_updated_at

        FROM users

        WHERE role = 'provider'
        AND available = TRUE

        ORDER BY name
        `
      );

      res.json({
        providers:
          result.rows.map(cleanUser)
      });

    } catch (error) {

      console.error(
        "PROVIDER SEARCH ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load available providers."
      });
    }
  }
);
// ================================
// CREATE REQUEST
// ================================

app.post(
  "/api/requests",
  authenticate,
  async (req, res) => {

    try {

      if (req.user.role !== "client") {

        return res.status(403).json({
          error:
            "Only clients can create requests."
        });
      }

      const {
        assistance_type,
        transport_type,
        area,
        amount,
        details,
        latitude,
        longitude
      } = req.body;

      if (
        !["SHORT TIME", "SLEEP OVER"]
          .includes(assistance_type)
      ) {

        return res.status(400).json({
          error:
            "Choose SHORT TIME or SLEEP OVER."
        });
      }

      if (
        !["PICK & DROP", "DRIVE THROUGH"]
          .includes(transport_type)
      ) {

        return res.status(400).json({
          error:
            "Choose PICK & DROP or DRIVE THROUGH."
        });
      }

      if (!area || !area.trim()) {

        return res.status(400).json({
          error:
            "Please enter the request area."
        });
      }

      const result = await pool.query(
        `
        INSERT INTO requests
        (
          client_id,
          assistance_type,
          transport_type,
          area,
          amount,
          details,
          latitude,
          longitude,
          status
        )

        VALUES
        (
          $1,$2,$3,$4,$5,$6,$7,$8,'OPEN'
        )

        RETURNING *
        `,
        [
          req.user.id,
          assistance_type,
          transport_type,
          area.trim(),
          amount || null,
          details || "",
          latitude || null,
          longitude || null
        ]
      );

      res.status(201).json({
        request: result.rows[0]
      });

    } catch (error) {

      console.error(
        "CREATE REQUEST ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to create request."
      });
    }
  }
);


// ================================
// CLIENT REQUESTS
// ================================

app.get(
  "/api/requests",
  authenticate,
  async (req, res) => {

    try {

      if (req.user.role === "client") {

        const result = await pool.query(
          `
          SELECT
            r.*,

            (
              SELECT COUNT(*)
              FROM interests i
              WHERE i.request_id = r.id
            ) AS interest_count

          FROM requests r

          WHERE r.client_id = $1

          ORDER BY
            r.created_at DESC
          `,
          [req.user.id]
        );

        return res.json({
          requests: result.rows
        });
      }


      // ============================
      // PROVIDER REQUEST FEED
      // ============================

      const result = await pool.query(
        `
        SELECT
          r.id,
          r.assistance_type,
          r.transport_type,
          r.area,
          r.amount,
          r.details,
          r.latitude,
          r.longitude,
          r.status,
          r.created_at,

          c.name AS client_name

        FROM requests r

        JOIN users c
          ON c.id = r.client_id

        WHERE r.status = 'OPEN'

        ORDER BY
          r.created_at DESC
        `
      );

      res.json({
        requests: result.rows
      });

    } catch (error) {

      console.error(
        "REQUEST LIST ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load requests."
      });
    }
  }
);


// ================================
// PROVIDER SHOWS INTEREST
// ================================

app.post(
  "/api/requests/:id/interests",
  authenticate,
  async (req, res) => {

    try {

      if (req.user.role !== "provider") {

        return res.status(403).json({
          error:
            "Only service providers can show interest."
        });
      }

      const request = await pool.query(
        `
        SELECT
          id,
          client_id,
          status

        FROM requests

        WHERE id = $1
        `,
        [req.params.id]
      );

      if (!request.rowCount) {

        return res.status(404).json({
          error:
            "Request not found."
        });
      }

      if (request.rows[0].status !== "OPEN") {

        return res.status(400).json({
          error:
            "This request is no longer open."
        });
      }

      const provider = await pool.query(
        `
        SELECT
          available

        FROM users

        WHERE id = $1
        AND role = 'provider'
        `,
        [req.user.id]
      );

      if (
        !provider.rowCount ||
        !provider.rows[0].available
      ) {

        return res.status(400).json({
          error:
            "Turn AVAILABLE on before showing interest."
        });
      }

      const result = await pool.query(
        `
        INSERT INTO interests
        (
          request_id,
          provider_id,
          location_enabled
        )

        VALUES
        ($1,$2,TRUE)

        ON CONFLICT
        (request_id,provider_id)

        DO UPDATE SET
          location_enabled = TRUE

        RETURNING *
        `,
        [
          req.params.id,
          req.user.id
        ]
      );

      res.status(201).json({
        message:
          "Interest sent successfully.",

        interest:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "INTEREST ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to send interest."
      });
    }
  }
);


// ================================
// CLIENT SEES INTERESTED PROVIDERS
// ================================

app.get(
  "/api/requests/:id/providers",
  authenticate,
  async (req, res) => {

    try {

      const request = await pool.query(
        `
        SELECT client_id
        FROM requests
        WHERE id = $1
        `,
        [req.params.id]
      );

      if (!request.rowCount) {

        return res.status(404).json({
          error:
            "Request not found."
        });
      }

      if (
        request.rows[0].client_id !==
        req.user.id
      ) {

        return res.status(403).json({
          error:
            "You do not own this request."
        });
      }

      const result = await pool.query(
        `
        SELECT

          u.id,
          u.name,
          u.age,
          u.photos,
          u.available,

          i.location_enabled,

          u.latitude,
          u.longitude,

          u.location_updated_at,

          i.created_at AS interested_at

        FROM interests i

        JOIN users u
          ON u.id = i.provider_id

        WHERE i.request_id = $1

        ORDER BY
          i.created_at ASC
        `,
        [req.params.id]
      );

      res.json({
        providers: result.rows
      });

    } catch (error) {

      console.error(
        "PROVIDER LIST ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load interested providers."
      });
    }
  }
);


// ================================
// ACCEPT PROVIDER
// ================================

app.post(
  "/api/requests/:id/accept",
  authenticate,
  async (req, res) => {

    try {

      if (req.user.role !== "client") {

        return res.status(403).json({
          error:
            "Only clients can accept providers."
        });
      }

      const {
        provider_id
      } = req.body;

      if (!provider_id) {

        return res.status(400).json({
          error:
            "Provider ID is required."
        });
      }

      const request = await pool.query(
        `
        SELECT *
        FROM requests

        WHERE id = $1
        AND client_id = $2
        `,
        [
          req.params.id,
          req.user.id
        ]
      );

      if (!request.rowCount) {

        return res.status(404).json({
          error:
            "Request not found."
        });
      }

      if (
        request.rows[0].status !==
        "OPEN"
      ) {

        return res.status(400).json({
          error:
            "This request has already been accepted."
        });
      }

      const interested =
        await pool.query(
          `
          SELECT *
          FROM interests

          WHERE request_id = $1
          AND provider_id = $2
          `,
          [
            req.params.id,
            provider_id
          ]
        );

      if (!interested.rowCount) {

        return res.status(400).json({
          error:
            "This provider has not shown interest."
        });
      }

      await pool.query(
        `
        UPDATE requests

        SET
          accepted_provider_id = $1,
          status = 'ACCEPTED',
          started_at = CURRENT_TIMESTAMP

        WHERE id = $2
        `,
        [
          provider_id,
          req.params.id
        ]
      );

      // Make the provider unavailable
      // while handling the accepted request.

      await pool.query(
        `
        UPDATE users

        SET available = FALSE

        WHERE id = $1
        `,
        [provider_id]
      );

      // Create a live location session.

      await pool.query(
        `
        INSERT INTO location_sessions
        (
          request_id,
          provider_id,
          active
        )

        VALUES
        ($1,$2,TRUE)
        `,
        [
          req.params.id,
          provider_id
        ]
      );

      const result =
        await pool.query(
          `
          SELECT

            r.*,

            c.name AS client_name,
            c.phone AS client_phone,

            p.name AS provider_name,
            p.phone AS provider_phone,
            p.age AS provider_age,
            p.photos AS provider_photos

          FROM requests r

          JOIN users c
            ON c.id = r.client_id

          JOIN users p
            ON p.id = r.accepted_provider_id

          WHERE r.id = $1
          `,
          [req.params.id]
        );

      res.json({
        message:
          "Provider accepted successfully.",

        match:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "ACCEPT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to accept provider."
      });
    }
  }
);
// ================================
// PROVIDER LIVE LOCATION UPDATE
// ================================

app.put(
  "/api/location",
  authenticate,
  async (req, res) => {

    try {

      if (req.user.role !== "provider") {
        return res.status(403).json({
          error:
            "Only service providers can share live location."
        });
      }

      const {
        latitude,
        longitude
      } = req.body;

      const lat = Number(latitude);
      const lng = Number(longitude);

      if (
        !Number.isFinite(lat) ||
        !Number.isFinite(lng) ||
        lat < -90 ||
        lat > 90 ||
        lng < -180 ||
        lng > 180
      ) {

        return res.status(400).json({
          error:
            "Invalid GPS coordinates."
        });
      }

      const active = await pool.query(
        `
        SELECT
          ls.request_id

        FROM location_sessions ls

        WHERE ls.provider_id = $1

        AND ls.active = TRUE

        AND EXISTS (
          SELECT 1
          FROM requests r
          WHERE r.id = ls.request_id
          AND r.status = 'ACCEPTED'
        )
        `,
        [req.user.id]
      );

      await pool.query(
        `
        UPDATE users

        SET
          latitude = $1,
          longitude = $2,
          location_enabled = TRUE,
          location_updated_at = CURRENT_TIMESTAMP

        WHERE id = $3
        `,
        [
          lat,
          lng,
          req.user.id
        ]
      );

      res.json({
        success: true,

        active_requests:
          active.rows.map(
            x => x.request_id
          )
      });

    } catch (error) {

      console.error(
        "LOCATION UPDATE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to update location."
      });
    }
  }
);


// ================================
// STOP PROVIDER LOCATION
// ================================

app.put(
  "/api/location/stop",
  authenticate,
  async (req, res) => {

    try {

      await pool.query(
        `
        UPDATE users

        SET
          location_enabled = FALSE,
          latitude = NULL,
          longitude = NULL,
          location_updated_at = NULL

        WHERE id = $1
        `,
        [req.user.id]
      );

      await pool.query(
        `
        UPDATE location_sessions

        SET
          active = FALSE,
          ended_at = CURRENT_TIMESTAMP

        WHERE provider_id = $1
        AND active = TRUE
        `,
        [req.user.id]
      );

      res.json({
        success: true,
        message:
          "Live location stopped."
      });

    } catch (error) {

      console.error(
        "LOCATION STOP ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to stop live location."
      });
    }
  }
);


// ================================
// CLIENT LIVE PROVIDER LOCATIONS
// ================================

app.get(
  "/api/requests/:id/live-locations",
  authenticate,
  async (req, res) => {

    try {

      const request = await pool.query(
        `
        SELECT
          client_id

        FROM requests

        WHERE id = $1
        `,
        [req.params.id]
      );

      if (!request.rowCount) {

        return res.status(404).json({
          error:
            "Request not found."
        });
      }

      if (
        request.rows[0].client_id !==
        req.user.id
      ) {

        return res.status(403).json({
          error:
            "You do not own this request."
        });
      }

      const result = await pool.query(
        `
        SELECT

          u.id,
          u.name,
          u.age,
          u.photos,

          u.latitude,
          u.longitude,

          u.location_updated_at,

          i.created_at AS interested_at

        FROM interests i

        JOIN users u
          ON u.id = i.provider_id

        WHERE i.request_id = $1

        AND i.location_enabled = TRUE

        AND u.location_enabled = TRUE

        AND u.latitude IS NOT NULL

        AND u.longitude IS NOT NULL

        ORDER BY
          i.created_at ASC
        `,
        [req.params.id]
      );

      res.json({
        locations:
          result.rows
      });

    } catch (error) {

      console.error(
        "LIVE LOCATION ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load live locations."
      });
    }
  }
);


// ================================
// PROVIDER ACCEPTED MATCHES
// ================================

app.get(
  "/api/provider/matches",
  authenticate,
  async (req, res) => {

    try {

      if (req.user.role !== "provider") {

        return res.status(403).json({
          error:
            "Only providers can access provider matches."
        });
      }

      const result = await pool.query(
        `
        SELECT

          r.id AS request_id,

          r.assistance_type,
          r.transport_type,

          r.area,
          r.amount,
          r.details,

          r.status,

          r.created_at,
          r.started_at,
          r.completed_at,

          c.id AS client_id,
          c.name AS client_name,
          c.phone AS client_phone

        FROM requests r

        JOIN users c
          ON c.id = r.client_id

        WHERE r.accepted_provider_id = $1

        ORDER BY
          r.created_at DESC
        `,
        [req.user.id]
      );

      res.json({
        matches:
          result.rows
      });

    } catch (error) {

      console.error(
        "PROVIDER MATCH ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load accepted matches."
      });
    }
  }
);


// ================================
// CLIENT ACCEPTED MATCHES
// ================================

app.get(
  "/api/client/matches",
  authenticate,
  async (req, res) => {

    try {

      if (req.user.role !== "client") {

        return res.status(403).json({
          error:
            "Only clients can access client matches."
        });
      }

      const result = await pool.query(
        `
        SELECT

          r.id AS request_id,

          r.assistance_type,
          r.transport_type,

          r.area,
          r.amount,
          r.details,

          r.status,

          r.created_at,
          r.started_at,
          r.completed_at,

          p.id AS provider_id,
          p.name AS provider_name,
          p.phone AS provider_phone,
          p.age AS provider_age,
          p.photos AS provider_photos

        FROM requests r

        JOIN users p
          ON p.id = r.accepted_provider_id

        WHERE r.client_id = $1

        AND r.accepted_provider_id IS NOT NULL

        ORDER BY
          r.created_at DESC
        `,
        [req.user.id]
      );

      res.json({
        matches:
          result.rows
      });

    } catch (error) {

      console.error(
        "CLIENT MATCH ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load accepted matches."
      });
    }
  }
);


// ================================
// REQUEST DETAILS / MATCH
// ================================

app.get(
  "/api/requests/:id/match",
  authenticate,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT

          r.id,
          r.client_id,
          r.accepted_provider_id,

          r.assistance_type,
          r.transport_type,

          r.area,
          r.amount,
          r.details,

          r.status,

          r.created_at,
          r.started_at,
          r.completed_at,

          c.name AS client_name,
          c.phone AS client_phone,

          p.name AS provider_name,
          p.phone AS provider_phone,
          p.age AS provider_age,
          p.photos AS provider_photos

        FROM requests r

        JOIN users c
          ON c.id = r.client_id

        LEFT JOIN users p
          ON p.id = r.accepted_provider_id

        WHERE r.id = $1

        AND (
          r.client_id = $2
          OR r.accepted_provider_id = $2
        )
        `,
        [
          req.params.id,
          req.user.id
        ]
      );

      if (!result.rowCount) {

        return res.status(404).json({
          error:
            "Match not found."
        });
      }

      const match = result.rows[0];

      res.json({
        match
      });

    } catch (error) {

      console.error(
        "MATCH DETAILS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load match."
      });
    }
  }
);


// ================================
// MARK REQUEST COMPLETED
// ================================

app.put(
  "/api/requests/:id/complete",
  authenticate,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT *

        FROM requests

        WHERE id = $1

        AND (
          client_id = $2
          OR accepted_provider_id = $2
        )
        `,
        [
          req.params.id,
          req.user.id
        ]
      );

      if (!result.rowCount) {

        return res.status(404).json({
          error:
            "Request not found."
        });
      }

      const request =
        result.rows[0];

      if (
        request.status !==
        "ACCEPTED"
      ) {

        return res.status(400).json({
          error:
            "Only an accepted request can be completed."
        });
      }

      await pool.query(
        `
        UPDATE requests

        SET
          status = 'COMPLETED',
          completed_at = CURRENT_TIMESTAMP

        WHERE id = $1
        `,
        [req.params.id]
      );

      await pool.query(
        `
        UPDATE location_sessions

        SET
          active = FALSE,
          ended_at = CURRENT_TIMESTAMP

        WHERE request_id = $1
        AND active = TRUE
        `,
        [req.params.id]
      );

      if (request.accepted_provider_id) {

        await pool.query(
          `
          UPDATE users

          SET
            location_enabled = FALSE,
            latitude = NULL,
            longitude = NULL,
            location_updated_at = NULL,
            available = FALSE

          WHERE id = $1
          `,
          [
            request.accepted_provider_id
          ]
        );
      }

      res.json({
        success: true,

        message:
          "Service completed and moved to history."
      });

    } catch (error) {

      console.error(
        "COMPLETE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to complete service."
      });
    }
  }
);


// ================================
// HISTORY
// ================================

app.get(
  "/api/history",
  authenticate,
  async (req, res) => {

    try {

      let result;

      if (req.user.role === "client") {

        result = await pool.query(
          `
          SELECT

            r.*,

            p.name AS provider_name,
            p.phone AS provider_phone,
            p.age AS provider_age,
            p.photos AS provider_photos

          FROM requests r

          LEFT JOIN users p
            ON p.id = r.accepted_provider_id

          WHERE r.client_id = $1

          AND r.status = 'COMPLETED'

          ORDER BY
            r.completed_at DESC
          `,
          [req.user.id]
        );

      } else {

        result = await pool.query(
          `
          SELECT

            r.*,

            c.name AS client_name,
            c.phone AS client_phone

          FROM requests r

          JOIN users c
            ON c.id = r.client_id

          WHERE r.accepted_provider_id = $1

          AND r.status = 'COMPLETED'

          ORDER BY
            r.completed_at DESC
          `,
          [req.user.id]
        );
      }

      res.json({
        history:
          result.rows
      });

    } catch (error) {

      console.error(
        "HISTORY ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load history."
      });
    }
  }
);
// ================================
// PRIVATE CHAT LIST
// ================================

app.get(
  "/api/chats",
  authenticate,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT

          r.id AS request_id,

          r.assistance_type,
          r.transport_type,
          r.area,
          r.amount,
          r.status,

          r.created_at,
          r.completed_at,

          c.id AS client_id,
          c.name AS client_name,
          c.phone AS client_phone,

          p.id AS provider_id,
          p.name AS provider_name,
          p.phone AS provider_phone,
          p.age AS provider_age,
          p.photos AS provider_photos

        FROM requests r

        JOIN users c
          ON c.id = r.client_id

        JOIN users p
          ON p.id = r.accepted_provider_id

        WHERE r.accepted_provider_id IS NOT NULL

        AND (
          r.client_id = $1
          OR r.accepted_provider_id = $1
        )

        ORDER BY
          r.created_at DESC
        `,
        [req.user.id]
      );

      res.json({
        chats: result.rows
      });

    } catch (error) {

      console.error(
        "CHAT LIST ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load conversations."
      });
    }
  }
);


// ================================
// CHAT MESSAGES
// ================================

app.get(
  "/api/chats/:requestId/messages",
  authenticate,
  async (req, res) => {

    try {

      const access = await pool.query(
        `
        SELECT id

        FROM requests

        WHERE id = $1

        AND (
          client_id = $2
          OR accepted_provider_id = $2
        )
        `,
        [
          req.params.requestId,
          req.user.id
        ]
      );

      if (!access.rowCount) {

        return res.status(403).json({
          error:
            "You do not have access to this conversation."
        });
      }

      const result = await pool.query(
        `
        SELECT

          m.id,
          m.sender_id,
          m.receiver_id,
          m.body,
          m.created_at,

          u.name AS sender_name

        FROM messages m

        JOIN users u
          ON u.id = m.sender_id

        WHERE m.request_id = $1

        ORDER BY
          m.created_at ASC
        `,
        [req.params.requestId]
      );

      res.json({
        messages:
          result.rows
      });

    } catch (error) {

      console.error(
        "MESSAGE LOAD ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load messages."
      });
    }
  }
);


// ================================
// SEND PRIVATE MESSAGE
// ================================

app.post(
  "/api/chats/:requestId/messages",
  authenticate,
  async (req, res) => {

    try {

      const body =
        String(req.body.body || "").trim();

      if (!body) {

        return res.status(400).json({
          error:
            "Message cannot be empty."
        });
      }

      const request =
        await pool.query(
          `
          SELECT

            id,
            client_id,
            accepted_provider_id,
            status

          FROM requests

          WHERE id = $1

          AND (
            client_id = $2
            OR accepted_provider_id = $2
          )
          `,
          [
            req.params.requestId,
            req.user.id
          ]
        );

      if (!request.rowCount) {

        return res.status(403).json({
          error:
            "You do not have access to this conversation."
        });
      }

      const r =
        request.rows[0];

      if (
        !["ACCEPTED", "COMPLETED"]
          .includes(r.status)
      ) {

        return res.status(403).json({
          error:
            "Chat is not available for this request."
        });
      }

      const receiverId =
        r.client_id === req.user.id
          ? r.accepted_provider_id
          : r.client_id;

      const result = await pool.query(
        `
        INSERT INTO messages
        (
          request_id,
          sender_id,
          receiver_id,
          body
        )

        VALUES
        ($1,$2,$3,$4)

        RETURNING
          id,
          sender_id,
          receiver_id,
          body,
          created_at
        `,
        [
          r.id,
          req.user.id,
          receiverId,
          body
        ]
      );

      res.status(201).json({
        message:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "SEND MESSAGE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to send message."
      });
    }
  }
);


// ================================
// LOCATION STATUS
// ================================

app.get(
  "/api/location/status",
  authenticate,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT

          location_enabled,
          latitude,
          longitude,
          location_updated_at

        FROM users

        WHERE id = $1
        `,
        [req.user.id]
      );

      if (!result.rowCount) {

        return res.status(404).json({
          error:
            "User not found."
        });
      }

      res.json({
        location:
          result.rows[0]
      });

    } catch (error) {

      res.status(500).json({
        error:
          "Unable to load location status."
      });
    }
  }
);


// ================================
// STOP ALL LOCATION SESSIONS
// ================================

app.post(
  "/api/location/end-session",
  authenticate,
  async (req, res) => {

    try {

      await pool.query(
        `
        UPDATE location_sessions

        SET
          active = FALSE,
          ended_at = CURRENT_TIMESTAMP

        WHERE provider_id = $1

        AND active = TRUE
        `,
        [req.user.id]
      );

      await pool.query(
        `
        UPDATE users

        SET
          location_enabled = FALSE,
          latitude = NULL,
          longitude = NULL,
          location_updated_at = NULL

        WHERE id = $1
        `,
        [req.user.id]
      );

      res.json({
        success: true,
        message:
          "Location sharing ended."
      });

    } catch (error) {

      console.error(
        "LOCATION SESSION ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to end location sharing."
      });
    }
  }
);


// ================================
// HEALTH CHECK
// ================================

app.get(
  "/api/health",
  async (req, res) => {

    try {

      await pool.query(
        "SELECT 1"
      );

      res.json({
        ok: true,
        app: "COME BY",
        slogan: "#TlaKwana"
      });

    } catch (error) {

      res.status(500).json({
        ok: false
      });
    }
  }
);


// ================================
// FRONTEND FALLBACK
// ================================

app.get(
  "*",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "index.html"
      )
    );
  }
);


// ================================
// START SERVER
// ================================

initDatabase()

  .then(() => {

    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `COME BY #TlaKwana running on port ${PORT}`
        );

      }
    );

  })

  .catch(error => {

    console.error(
      "DATABASE STARTUP ERROR:",
      error
    );

    process.exit(1);
  });
