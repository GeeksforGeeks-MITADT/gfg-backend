const express = require('express')
const cors = require('cors')
const { Low } = require('lowdb')
const { JSONFile } = require('lowdb/node')

const app = express()
const PORT = process.env.PORT || 4000 // ✅ Use Render's dynamic port

const adapter = new JSONFile('events.json')
const db = new Low(adapter, { events: [] })

app.use(cors())
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

    if (apiKey !== 'admin123') {
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
