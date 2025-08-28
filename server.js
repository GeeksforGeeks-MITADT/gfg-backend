import express from 'express'
import cors from 'cors'
import { Low } from 'lowdb'
import { JSONFile } from 'lowdb/node'
import dotenv from 'dotenv'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 4000 // ✅ Use Render's dynamic port

const adapter = new JSONFile('events.json')
const db = new Low(adapter, { events: [] })

// Configure CORS for production security
const corsOptions = {
  // Reflect the request origin or your specified CORS_ORIGIN
  origin: process.env.CORS_ORIGIN || '*',
  optionsSuccessStatus: 200,
}
app.use(cors(corsOptions))
app.use(express.json())

// 🌐 Health check route
app.get('/', (req, res) => {
  res.send('🎉 GFG Backend is running!')
})

async function startServer() {
  await db.read()

  if (!db.data) {
    db.data = { events: [] }
    await db.write()
  }

  // GET all events
  app.get('/events', (req, res) => {
    res.json(db.data.events)
  })

  // POST new event
  app.post('/events', async (req, res) => {
    const {
      title, description, category, date, time, duration, location, speaker, prerequisites, apiKey
    } = req.body

    // Get admin secret key from environment variables
    const adminSecretKey = process.env.ADMIN_SECRET_KEY

    if (!adminSecretKey) {
      console.error('ADMIN_SECRET_KEY not configured in environment variables')
      return res.status(500).json({ message: 'Server configuration error' })
    }

    if (apiKey !== adminSecretKey) {
      console.warn('Failed admin authentication attempt from:', req.ip)
      return res.status(401).json({ message: 'Unauthorized' })
    }

    const newEvent = {
      id: Date.now().toString(),
      title,
      description,
      category,
      date,
      time,
      duration,
      location,
      speaker,
      prerequisites
    }

    db.data.events.push(newEvent)
    await db.write()
    res.status(201).json(newEvent)
  })

  app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`)
  })
}

startServer()
