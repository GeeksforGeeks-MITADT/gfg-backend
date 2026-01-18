import express from 'express'
import cors from 'cors'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { PrismaClient } from '@prisma/client'
import dotenv from 'dotenv'
import multer from 'multer'
import path from 'path'
import { fileURLToPath } from 'url'
import fs from 'fs'
import { createClient } from '@supabase/supabase-js'

dotenv.config()

// Initialize Supabase client for storage
const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_ANON_KEY || ''
)

// Get directory name for ES modules
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads')
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true })
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir)
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, 'poster-' + uniqueSuffix + path.extname(file.originalname))
  }
})

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase())
    const mimetype = allowedTypes.test(file.mimetype)
    if (extname && mimetype) {
      cb(null, true)
    } else {
      cb(new Error('Only image files are allowed'))
    }
  }
})

const app = express()
const prisma = new PrismaClient()
const PORT = process.env.PORT || 4000

// JWT Configuration
function getJwtConfig() {
  const secret = process.env.JWT_SECRET || 'gfg-default-secret-change-in-production'
  return { secret, expiresIn: '7d' }
}

// JWT Verification Middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization

  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided' })
  }

  const token = authHeader.slice(7)

  try {
    const { secret } = getJwtConfig()
    const payload = jwt.verify(token, secret)
    req.user = payload
    next()
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' })
  }
}

// Admin check middleware
function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ message: 'Authentication required' })
  }
  if (!['ADMIN', 'SUPER_ADMIN'].includes(req.user.role)) {
    return res.status(403).json({ message: 'Admin access required' })
  }
  next()
}

// Configure CORS
const corsOptions = {
  origin: process.env.CORS_ORIGIN || '*',
  optionsSuccessStatus: 200,
}
app.use(cors(corsOptions))
app.use(express.json())

// Serve uploaded files statically
app.use('/uploads', express.static(uploadsDir))

// Image upload endpoint
app.post('/upload', verifyToken, requireAdmin, upload.single('poster'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No image file uploaded' })
  }

  const imageUrl = `${process.env.BACKEND_URL || `http://localhost:${PORT}`}/uploads/${req.file.filename}`
  res.json({
    message: 'Image uploaded successfully',
    url: imageUrl,
    filename: req.file.filename
  })
})

// Health check route
app.get('/', (req, res) => {
  res.send('🎉 GFG Backend is running with Supabase!')
})

// ==================== AUTH ROUTES ====================

// Register new user
app.post('/auth/register', async (req, res) => {
  try {
    const { email, username, password, displayName, phone, college, branch, year } = req.body

    if (!email || !username || !password) {
      return res.status(400).json({ message: 'Email, username, and password are required' })
    }

    // Check if user exists
    const existingUser = await prisma.user.findFirst({
      where: { OR: [{ email }, { username }] }
    })

    if (existingUser) {
      return res.status(400).json({
        message: existingUser.email === email ? 'Email already in use' : 'Username taken'
      })
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10)

    // Count existing users (first user becomes SUPER_ADMIN)
    const userCount = await prisma.user.count()
    const isFirstUser = userCount === 0

    // Create user with profile fields
    const newUser = await prisma.user.create({
      data: {
        email,
        username,
        passwordHash,
        displayName: displayName || username,
        phone,
        college,
        branch,
        year,
        role: isFirstUser ? 'SUPER_ADMIN' : 'USER',
      },
      select: {
        id: true,
        email: true,
        username: true,
        displayName: true,
        avatarUrl: true,
        phone: true,
        college: true,
        branch: true,
        year: true,
        role: true,
        createdAt: true
      }
    })

    // Generate token
    const { secret } = getJwtConfig()
    const token = jwt.sign(
      { userId: newUser.id, role: newUser.role },
      secret,
      { expiresIn: '7d' }
    )

    res.status(201).json({
      user: newUser,
      token,
      message: isFirstUser ? 'Account created as Super Admin!' : 'Account created successfully!'
    })
  } catch (error) {
    console.error('Registration error:', error)
    res.status(500).json({ message: 'Registration failed' })
  }
})

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' })
    }

    const user = await prisma.user.findUnique({ where: { email } })

    if (!user || !user.passwordHash) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    if (user.isBanned) {
      return res.status(403).json({ message: 'Account banned' })
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash)
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    // Generate token
    const { secret } = getJwtConfig()
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      secret,
      { expiresIn: '7d' }
    )

    res.json({
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        displayName: user.displayName,
        avatarUrl: user.avatarUrl,
        role: user.role,
      },
      token
    })
  } catch (error) {
    console.error('Login error:', error)
    res.status(500).json({ message: 'Login failed' })
  }
})

// Get current user
app.get('/auth/me', verifyToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: {
        id: true,
        email: true,
        username: true,
        displayName: true,
        avatarUrl: true,
        bio: true,
        role: true,
        createdAt: true
      }
    })

    if (!user) {
      return res.status(404).json({ message: 'User not found' })
    }

    res.json({ user })
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch user' })
  }
})

// Get current user dashboard with full stats and badges
app.get('/auth/me/dashboard', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId

    // Get user with all related data
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true, email: true, username: true, displayName: true, avatarUrl: true,
        bio: true, phone: true, college: true, branch: true, year: true, role: true, createdAt: true,
        eventRegistrations: {
          where: { status: 'confirmed' },
          include: { event: { select: { id: true, title: true, category: true, startDate: true, posterUrl: true, themeColor: true } } },
          orderBy: { createdAt: 'desc' }
        },
        testimonials: { select: { id: true, content: true, isApproved: true, isFeatured: true, createdAt: true } }
      }
    })

    if (!user) {
      return res.status(404).json({ message: 'User not found' })
    }

    // Get counts
    const [eventCount, feedbackCount, photoCount, commentCount, checkinCount] = await Promise.all([
      prisma.eventRegistration.count({ where: { userId, status: 'confirmed' } }),
      prisma.eventFeedback.count({ where: { userId } }),
      prisma.eventPhoto.count({ where: { userId } }),
      prisma.eventComment.count({ where: { userId } }),
      prisma.eventCheckin.count({ where: { userId } })
    ])

    // Get total user count for "Early Bird" badge
    const userRank = await prisma.user.count({ where: { createdAt: { lte: user.createdAt } } })

    // Calculate badges
    const badges = []

    // Early Bird - First 10 members
    if (userRank <= 10) {
      badges.push({ id: 'early_bird', name: 'Early Bird', icon: '🐦', description: 'One of the first 10 members' })
    }

    // Founding Member - First 50 members
    if (userRank <= 50) {
      badges.push({ id: 'founding_member', name: 'Founding Member', icon: '⭐', description: 'One of the first 50 members' })
    }

    // Event Enthusiast - 5+ events
    if (eventCount >= 5) {
      badges.push({ id: 'event_enthusiast', name: 'Event Enthusiast', icon: '🎪', description: 'Attended 5+ events' })
    }

    // Event Regular - 3+ events
    if (eventCount >= 3) {
      badges.push({ id: 'event_regular', name: 'Regular Attendee', icon: '🎫', description: 'Attended 3+ events' })
    }

    // First Event
    if (eventCount >= 1) {
      badges.push({ id: 'first_event', name: 'First Event', icon: '🎉', description: 'Attended your first event' })
    }

    // Critic - 10+ reviews
    if (feedbackCount >= 10) {
      badges.push({ id: 'critic', name: 'Critic', icon: '📝', description: 'Gave 10+ event reviews' })
    }

    // Reviewer - 5+ reviews
    if (feedbackCount >= 5) {
      badges.push({ id: 'reviewer', name: 'Reviewer', icon: '✍️', description: 'Gave 5+ event reviews' })
    }

    // Photographer - 10+ photos
    if (photoCount >= 10) {
      badges.push({ id: 'photographer', name: 'Photographer', icon: '📷', description: 'Shared 10+ event photos' })
    }

    // Shutterbug - 5+ photos
    if (photoCount >= 5) {
      badges.push({ id: 'shutterbug', name: 'Shutterbug', icon: '📸', description: 'Shared 5+ event photos' })
    }

    // Discusser - 25+ comments
    if (commentCount >= 25) {
      badges.push({ id: 'discusser', name: 'Discusser', icon: '💬', description: 'Posted 25+ comments' })
    }

    // Chatterbox - 10+ comments
    if (commentCount >= 10) {
      badges.push({ id: 'chatterbox', name: 'Chatterbox', icon: '🗣️', description: 'Posted 10+ comments' })
    }

    // Punctual - checked in to 3+ events
    if (checkinCount >= 3) {
      badges.push({ id: 'punctual', name: 'Punctual', icon: '⏰', description: 'Checked in to 3+ events on time' })
    }

    res.json({
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        displayName: user.displayName,
        avatarUrl: user.avatarUrl,
        bio: user.bio,
        phone: user.phone,
        college: user.college,
        branch: user.branch,
        year: user.year,
        role: user.role,
        createdAt: user.createdAt
      },
      stats: {
        eventsAttended: eventCount,
        feedbackGiven: feedbackCount,
        photosShared: photoCount,
        commentsPosted: commentCount,
        checkIns: checkinCount
      },
      badges,
      eventsAttended: user.eventRegistrations.map(r => r.event),
      testimonials: user.testimonials
    })
  } catch (error) {
    console.error('Dashboard error:', error)
    res.status(500).json({ message: 'Failed to fetch dashboard' })
  }
})

// Promote user to admin (super admin only)
app.post('/auth/promote/:userId', verifyToken, requireAdmin, async (req, res) => {
  try {
    if (req.user.role !== 'SUPER_ADMIN') {
      return res.status(403).json({ message: 'Only Super Admin can promote users' })
    }

    const user = await prisma.user.update({
      where: { id: req.params.userId },
      data: { role: 'ADMIN' },
      select: { id: true, username: true, role: true }
    })

    res.json({ message: 'User promoted to admin', user })
  } catch (error) {
    res.status(500).json({ message: 'Failed to promote user' })
  }
})

// List all users (admin only)
app.get('/auth/users', verifyToken, requireAdmin, async (req, res) => {
  const users = await prisma.user.findMany({
    select: {
      id: true,
      email: true,
      username: true,
      displayName: true,
      avatarUrl: true,
      role: true,
      createdAt: true
    }
  })
  res.json({ users })
})

// ==================== FILE UPLOAD ROUTES (Supabase Storage) ====================

// Upload file to Supabase Storage
app.post('/upload', verifyToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' })
    }

    // Check if Supabase is configured
    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) {
      return res.status(500).json({ message: 'Supabase storage not configured' })
    }

    const fileBuffer = fs.readFileSync(req.file.path)
    const fileName = `${Date.now()}-${req.file.originalname.replace(/\s/g, '_')}`
    const bucket = req.body.bucket || 'posters' // Default to posters bucket

    // Upload to Supabase Storage
    const { data, error } = await supabase.storage
      .from(bucket)
      .upload(fileName, fileBuffer, {
        contentType: req.file.mimetype,
        upsert: false
      })

    // Clean up local file
    fs.unlinkSync(req.file.path)

    if (error) {
      console.error('Supabase upload error:', error)
      return res.status(500).json({ message: 'Failed to upload to storage', error: error.message })
    }

    // Get public URL
    const { data: publicUrlData } = supabase.storage
      .from(bucket)
      .getPublicUrl(fileName)

    res.json({
      message: 'File uploaded successfully',
      url: publicUrlData.publicUrl,
      path: data.path
    })
  } catch (error) {
    console.error('Upload error:', error)
    // Clean up local file if it exists
    if (req.file?.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path)
    }
    res.status(500).json({ message: 'Upload failed', error: error.message })
  }
})

// Upload multiple photos (for event recaps)
app.post('/upload/multiple', verifyToken, upload.array('files', 20), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: 'No files uploaded' })
    }

    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) {
      return res.status(500).json({ message: 'Supabase storage not configured' })
    }

    const bucket = req.body.bucket || 'event-photos'
    const uploadedUrls = []

    for (const file of req.files) {
      const fileBuffer = fs.readFileSync(file.path)
      const fileName = `${Date.now()}-${Math.random().toString(36).substring(7)}-${file.originalname.replace(/\s/g, '_')}`

      const { data, error } = await supabase.storage
        .from(bucket)
        .upload(fileName, fileBuffer, {
          contentType: file.mimetype,
          upsert: false
        })

      // Clean up local file
      fs.unlinkSync(file.path)

      if (!error) {
        const { data: publicUrlData } = supabase.storage
          .from(bucket)
          .getPublicUrl(fileName)
        uploadedUrls.push(publicUrlData.publicUrl)
      }
    }

    res.json({
      message: `${uploadedUrls.length} files uploaded successfully`,
      urls: uploadedUrls
    })
  } catch (error) {
    console.error('Multiple upload error:', error)
    // Clean up any remaining local files
    if (req.files) {
      for (const file of req.files) {
        if (fs.existsSync(file.path)) fs.unlinkSync(file.path)
      }
    }
    res.status(500).json({ message: 'Upload failed', error: error.message })
  }
})

// ==================== GFG EVENT ROUTES ====================

// GET all events (public)
app.get('/events', async (req, res) => {
  try {
    const events = await prisma.gfgEvent.findMany({
      where: { isPublished: true },
      orderBy: { startDate: 'desc' },
      include: {
        createdBy: {
          select: { id: true, username: true, displayName: true }
        }
      }
    })

    // Transform to match frontend expected format
    const formattedEvents = events.map(event => ({
      id: event.id,
      title: event.title,
      description: event.description,
      category: event.category,
      date: `${event.startDate.toISOString().split('T')[0]} to ${event.endDate.toISOString().split('T')[0]}`,
      time: event.startTime && event.endTime ? `${event.startTime} - ${event.endTime}` : null,
      speakers: event.speakers,
      prerequisites: event.prerequisites,
      registrationLink: event.registrationLink,
      posterUrl: event.posterUrl,
      location: event.location,
      createdAt: event.createdAt,
      createdBy: event.createdBy
    }))

    res.json(formattedEvents)
  } catch (error) {
    console.error('Failed to fetch events:', error)
    res.status(500).json({ message: 'Failed to fetch events' })
  }
})

// GET single event (public)
app.get('/events/:id', async (req, res) => {
  try {
    const event = await prisma.gfgEvent.findUnique({
      where: { id: req.params.id },
      include: {
        createdBy: {
          select: { id: true, username: true, displayName: true }
        },
        _count: {
          select: { registrations: true }
        }
      }
    })

    if (!event) {
      return res.status(404).json({ message: 'Event not found' })
    }

    // Format for frontend
    const formattedEvent = {
      ...event,
      date: `${event.startDate.toISOString().split('T')[0]} to ${event.endDate.toISOString().split('T')[0]}`,
      time: event.startTime && event.endTime ? `${event.startTime} - ${event.endTime}` : null,
      // Use manual registrationCount if set, otherwise use actual registrations
      registrationCount: event.registrationCount || event._count.registrations,
      isPast: new Date(event.endDate) < new Date()
    }

    delete formattedEvent._count

    res.json(formattedEvent)
  } catch (error) {
    console.error('Fetch event error:', error)
    res.status(500).json({ message: 'Failed to fetch event' })
  }
})

// POST new event (admin only)
app.post('/events', verifyToken, requireAdmin, async (req, res) => {
  try {
    const {
      title, description, category, date, time, speakers, prerequisites, registrationLink, posterUrl, location
    } = req.body

    if (!title || !description) {
      return res.status(400).json({ message: 'Title and description are required' })
    }

    // Parse date range (e.g., "2024-01-15 to 2024-01-16")
    let startDate = new Date()
    let endDate = new Date()

    if (date) {
      const [start, end] = date.split(' to ')
      startDate = new Date(start)
      endDate = end ? new Date(end) : new Date(start)
    }

    // Parse time (e.g., "10:00 - 14:00")
    let startTime = null
    let endTime = null

    if (time) {
      const [start, end] = time.split(' - ')
      startTime = start?.trim()
      endTime = end?.trim()
    }

    const newEvent = await prisma.gfgEvent.create({
      data: {
        title,
        description,
        category: category || 'Technical',
        startDate,
        endDate,
        startTime,
        endTime,
        speakers,
        prerequisites,
        registrationLink,
        posterUrl,
        location,
        createdById: req.user.userId
      }
    })

    res.status(201).json(newEvent)
  } catch (error) {
    console.error('Failed to create event:', error)
    res.status(500).json({ message: 'Failed to create event' })
  }
})

// PUT update event (admin only)
app.put('/events/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const {
      title, description, category, date, time, speakers, prerequisites,
      registrationLink, posterUrl, location, themeColor, registrationCount, whatsappLink
    } = req.body

    // Parse date and time if provided
    let updateData = {}

    if (title) updateData.title = title
    if (description) updateData.description = description
    if (category) updateData.category = category
    if (speakers !== undefined) updateData.speakers = speakers
    if (prerequisites !== undefined) updateData.prerequisites = prerequisites
    if (registrationLink !== undefined) updateData.registrationLink = registrationLink
    if (posterUrl !== undefined) updateData.posterUrl = posterUrl
    if (location !== undefined) updateData.location = location
    if (themeColor !== undefined) updateData.themeColor = themeColor
    if (whatsappLink !== undefined) updateData.whatsappLink = whatsappLink
    if (registrationCount !== undefined) updateData.registrationCount = parseInt(registrationCount) || 0

    if (date) {
      const [start, end] = date.split(' to ')
      updateData.startDate = new Date(start)
      updateData.endDate = end ? new Date(end) : new Date(start)
    }

    if (time) {
      const [start, end] = time.split(' - ')
      updateData.startTime = start?.trim()
      updateData.endTime = end?.trim()
    }

    const updatedEvent = await prisma.gfgEvent.update({
      where: { id: req.params.id },
      data: updateData
    })

    res.json(updatedEvent)
  } catch (error) {
    res.status(500).json({ message: 'Failed to update event' })
  }
})

// DELETE event (admin only)
app.delete('/events/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    await prisma.gfgEvent.delete({
      where: { id: req.params.id }
    })

    res.json({ message: 'Event deleted successfully' })
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete event' })
  }
})

// PUT event recap (admin only) - Add post-event content
app.put('/events/:id/recap', verifyToken, requireAdmin, async (req, res) => {
  try {
    const {
      recapSummary,
      recapHighlights,
      recapPhotos,
      recapVideoUrl,
      winners,
      themeColor,
      isRecapPublished
    } = req.body

    const updateData = {}

    if (recapSummary !== undefined) updateData.recapSummary = recapSummary
    if (recapHighlights !== undefined) updateData.recapHighlights = recapHighlights
    if (recapPhotos !== undefined) updateData.recapPhotos = recapPhotos
    if (recapVideoUrl !== undefined) updateData.recapVideoUrl = recapVideoUrl
    if (winners !== undefined) updateData.winners = winners
    if (themeColor !== undefined) updateData.themeColor = themeColor
    if (isRecapPublished !== undefined) updateData.isRecapPublished = isRecapPublished

    const updatedEvent = await prisma.gfgEvent.update({
      where: { id: req.params.id },
      data: updateData
    })

    res.json({
      message: 'Event recap updated successfully',
      event: updatedEvent
    })
  } catch (error) {
    console.error('Recap update error:', error)
    res.status(500).json({ message: 'Failed to update event recap' })
  }
})

// ==================== EVENT REGISTRATION ROUTES ====================

// Register for an event
app.post('/events/:id/register', verifyToken, async (req, res) => {
  try {
    const eventId = req.params.id
    const userId = req.user.userId

    // Check if event exists
    const event = await prisma.gfgEvent.findUnique({
      where: { id: eventId },
      include: { _count: { select: { registrations: true } } }
    })

    if (!event) {
      return res.status(404).json({ message: 'Event not found' })
    }

    // Check if already registered
    const existing = await prisma.eventRegistration.findUnique({
      where: { eventId_userId: { eventId, userId } }
    })

    if (existing) {
      return res.status(400).json({ message: 'Already registered for this event' })
    }

    // Check max participants - add to waitlist if full
    let status = 'confirmed'
    if (event.maxParticipants) {
      const confirmedCount = await prisma.eventRegistration.count({
        where: { eventId, status: 'confirmed' }
      })
      if (confirmedCount >= event.maxParticipants) {
        status = 'waitlisted'
      }
    }

    // Create registration
    const registration = await prisma.eventRegistration.create({
      data: { eventId, userId, status },
      include: { event: { select: { title: true } } }
    })

    const message = status === 'waitlisted'
      ? `Added to waitlist for ${registration.event.title}`
      : `Registered for ${registration.event.title}`

    res.status(201).json({
      message: `Successfully registered for ${registration.event.title}`,
      registration
    })
  } catch (error) {
    console.error('Registration error:', error)
    res.status(500).json({ message: 'Failed to register for event' })
  }
})

// Unregister from an event
app.delete('/events/:id/register', verifyToken, async (req, res) => {
  try {
    const eventId = req.params.id
    const userId = req.user.userId

    await prisma.eventRegistration.delete({
      where: { eventId_userId: { eventId, userId } }
    })

    res.json({ message: 'Successfully unregistered from event' })
  } catch (error) {
    res.status(500).json({ message: 'Failed to unregister from event' })
  }
})

// Get registrations for an event (admin only)
app.get('/events/:id/registrations', verifyToken, requireAdmin, async (req, res) => {
  try {
    const registrations = await prisma.eventRegistration.findMany({
      where: { eventId: req.params.id },
      include: {
        user: {
          select: {
            id: true,
            displayName: true,
            email: true,
            phone: true,
            college: true,
            branch: true,
            year: true
          }
        }
      },
      orderBy: { createdAt: 'asc' }
    })

    res.json(registrations)
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch registrations' })
  }
})

// Check if current user is registered for an event
app.get('/events/:id/registration-status', verifyToken, async (req, res) => {
  try {
    const registration = await prisma.eventRegistration.findUnique({
      where: {
        eventId_userId: {
          eventId: req.params.id,
          userId: req.user.userId
        }
      }
    })

    res.json({ isRegistered: !!registration, status: registration?.status })
  } catch (error) {
    res.status(500).json({ message: 'Failed to check registration status' })
  }
})

// ==================== FEEDBACK ROUTES ====================

// Submit feedback for an event
app.post('/events/:id/feedback', verifyToken, async (req, res) => {
  try {
    const { rating, comment } = req.body
    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ message: 'Rating must be 1-5' })
    }

    const feedback = await prisma.eventFeedback.upsert({
      where: { eventId_userId: { eventId: req.params.id, userId: req.user.userId } },
      update: { rating, comment },
      create: { eventId: req.params.id, userId: req.user.userId, rating, comment }
    })

    res.json({ message: 'Feedback submitted', feedback })
  } catch (error) {
    res.status(500).json({ message: 'Failed to submit feedback' })
  }
})

// Get feedback for an event
app.get('/events/:id/feedback', async (req, res) => {
  try {
    const feedbacks = await prisma.eventFeedback.findMany({
      where: { eventId: req.params.id },
      include: { user: { select: { displayName: true, username: true } } },
      orderBy: { createdAt: 'desc' }
    })

    const avgRating = feedbacks.length
      ? feedbacks.reduce((sum, f) => sum + f.rating, 0) / feedbacks.length
      : 0

    res.json({ feedbacks, avgRating: Math.round(avgRating * 10) / 10, count: feedbacks.length })
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch feedback' })
  }
})

// ==================== CHECK-IN ROUTES ====================

// Generate check-in info (returns event ID for QR)
app.get('/events/:id/checkin-qr', verifyToken, requireAdmin, async (req, res) => {
  const checkinUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/events/${req.params.id}/checkin`
  res.json({ eventId: req.params.id, checkinUrl })
})

// Check in to event
app.post('/events/:id/checkin', verifyToken, async (req, res) => {
  try {
    // Verify user is registered
    const registration = await prisma.eventRegistration.findUnique({
      where: { eventId_userId: { eventId: req.params.id, userId: req.user.userId } }
    })

    if (!registration) {
      return res.status(400).json({ message: 'You must be registered to check in' })
    }

    const checkin = await prisma.eventCheckin.upsert({
      where: { eventId_userId: { eventId: req.params.id, userId: req.user.userId } },
      update: {},
      create: { eventId: req.params.id, userId: req.user.userId }
    })

    res.json({ message: 'Checked in successfully', checkin })
  } catch (error) {
    res.status(500).json({ message: 'Check-in failed' })
  }
})

// Get attendance list
app.get('/events/:id/attendance', verifyToken, requireAdmin, async (req, res) => {
  try {
    const checkins = await prisma.eventCheckin.findMany({
      where: { eventId: req.params.id },
      include: { user: { select: { id: true, displayName: true, username: true, email: true, college: true } } }
    })
    res.json(checkins)
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch attendance' })
  }
})

// ==================== PHOTO WALL ROUTES ====================

// Upload event photo
app.post('/events/:id/photos', verifyToken, async (req, res) => {
  try {
    const { photoUrl, caption } = req.body
    if (!photoUrl) return res.status(400).json({ message: 'Photo URL required' })

    const photo = await prisma.eventPhoto.create({
      data: { eventId: req.params.id, userId: req.user.userId, photoUrl, caption }
    })

    res.json({ message: 'Photo added', photo })
  } catch (error) {
    res.status(500).json({ message: 'Failed to add photo' })
  }
})

// Get event photos
app.get('/events/:id/photos', async (req, res) => {
  try {
    const photos = await prisma.eventPhoto.findMany({
      where: { eventId: req.params.id },
      include: { user: { select: { displayName: true, username: true } } },
      orderBy: { createdAt: 'desc' }
    })
    res.json(photos)
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch photos' })
  }
})

// ==================== COMMENTS ROUTES ====================

// Add comment
app.post('/events/:id/comments', verifyToken, async (req, res) => {
  try {
    const { content } = req.body
    if (!content?.trim()) return res.status(400).json({ message: 'Comment required' })

    const comment = await prisma.eventComment.create({
      data: { eventId: req.params.id, userId: req.user.userId, content },
      include: { user: { select: { displayName: true, username: true } } }
    })

    res.json(comment)
  } catch (error) {
    res.status(500).json({ message: 'Failed to add comment' })
  }
})

// Get comments
app.get('/events/:id/comments', async (req, res) => {
  try {
    const comments = await prisma.eventComment.findMany({
      where: { eventId: req.params.id },
      include: { user: { select: { displayName: true, username: true } } },
      orderBy: { createdAt: 'desc' }
    })
    res.json(comments)
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch comments' })
  }
})

// ==================== WAITLIST ROUTES ====================

// Get waitlist
app.get('/events/:id/waitlist', verifyToken, requireAdmin, async (req, res) => {
  try {
    const waitlist = await prisma.eventRegistration.findMany({
      where: { eventId: req.params.id, status: 'waitlisted' },
      include: { user: { select: { id: true, displayName: true, username: true, email: true } } },
      orderBy: { createdAt: 'asc' }
    })
    res.json(waitlist)
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch waitlist' })
  }
})

// Promote from waitlist
app.post('/events/:id/promote/:userId', verifyToken, requireAdmin, async (req, res) => {
  try {
    const registration = await prisma.eventRegistration.update({
      where: { eventId_userId: { eventId: req.params.id, userId: req.params.userId } },
      data: { status: 'confirmed' }
    })
    res.json({ message: 'User promoted from waitlist', registration })
  } catch (error) {
    res.status(500).json({ message: 'Failed to promote user' })
  }
})

// ==================== EXPORT CSV ROUTE ====================

app.get('/events/:id/export-csv', verifyToken, requireAdmin, async (req, res) => {
  try {
    const registrations = await prisma.eventRegistration.findMany({
      where: { eventId: req.params.id },
      include: { user: { select: { displayName: true, username: true, email: true, phone: true, college: true, branch: true, year: true } } },
      orderBy: { createdAt: 'asc' }
    })

    // Create CSV
    const headers = ['Name', 'Username', 'Email', 'Phone', 'College', 'Branch', 'Year', 'Status', 'Registered At']
    const rows = registrations.map(r => [
      r.user.displayName || '',
      r.user.username,
      r.user.email,
      r.user.phone || '',
      r.user.college || '',
      r.user.branch || '',
      r.user.year || '',
      r.status,
      r.createdAt.toISOString()
    ])

    const csv = [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n')

    res.setHeader('Content-Type', 'text/csv')
    res.setHeader('Content-Disposition', `attachment; filename="event-${req.params.id}-attendees.csv"`)
    res.send(csv)
  } catch (error) {
    res.status(500).json({ message: 'Failed to export CSV' })
  }
})

// ==================== TESTIMONIALS ROUTES ====================

// Get approved testimonials
app.get('/testimonials', async (req, res) => {
  try {
    const testimonials = await prisma.testimonial.findMany({
      where: { isApproved: true },
      include: { user: { select: { displayName: true, username: true, college: true } } },
      orderBy: [{ isFeatured: 'desc' }, { createdAt: 'desc' }]
    })
    res.json(testimonials)
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch testimonials' })
  }
})

// Submit testimonial
app.post('/testimonials', verifyToken, async (req, res) => {
  try {
    const { content } = req.body
    if (!content?.trim()) return res.status(400).json({ message: 'Content required' })

    const testimonial = await prisma.testimonial.create({
      data: { userId: req.user.userId, content }
    })

    res.json({ message: 'Testimonial submitted for review', testimonial })
  } catch (error) {
    res.status(500).json({ message: 'Failed to submit testimonial' })
  }
})

// Admin: Get all testimonials
app.get('/admin/testimonials', verifyToken, requireAdmin, async (req, res) => {
  try {
    const testimonials = await prisma.testimonial.findMany({
      include: { user: { select: { displayName: true, username: true } } },
      orderBy: { createdAt: 'desc' }
    })
    res.json(testimonials)
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch testimonials' })
  }
})

// Admin: Approve/feature testimonial
app.put('/admin/testimonials/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { isApproved, isFeatured } = req.body
    const testimonial = await prisma.testimonial.update({
      where: { id: req.params.id },
      data: { isApproved, isFeatured }
    })
    res.json(testimonial)
  } catch (error) {
    res.status(500).json({ message: 'Failed to update testimonial' })
  }
})

// ==================== USER PROFILE ROUTES ====================

// Get public profile (supports lookup by ID or username)
app.get('/users/:id/profile', async (req, res) => {
  try {
    // Try to find by ID first, then by username
    let user = await prisma.user.findUnique({
      where: { id: req.params.id },
      select: {
        id: true, username: true, displayName: true, bio: true, college: true, branch: true, year: true, createdAt: true,
        eventRegistrations: {
          where: { status: 'confirmed' },
          include: { event: { select: { id: true, title: true, category: true, startDate: true } } }
        },
        _count: { select: { eventRegistrations: true, eventFeedbacks: true } }
      }
    })

    // If not found by ID, try by username
    if (!user) {
      user = await prisma.user.findUnique({
        where: { username: req.params.id },
        select: {
          id: true, username: true, displayName: true, bio: true, college: true, branch: true, year: true, createdAt: true,
          eventRegistrations: {
            where: { status: 'confirmed' },
            include: { event: { select: { id: true, title: true, category: true, startDate: true } } }
          },
          _count: { select: { eventRegistrations: true, eventFeedbacks: true } }
        }
      })
    }

    if (!user) return res.status(404).json({ message: 'User not found' })
    res.json(user)
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch profile' })
  }
})

// Update own profile
app.put('/users/profile', verifyToken, async (req, res) => {
  try {
    const { displayName, bio, phone, college, branch, year } = req.body
    const user = await prisma.user.update({
      where: { id: req.user.userId },
      data: { displayName, bio, phone, college, branch, year },
      select: { id: true, username: true, displayName: true, bio: true, email: true, phone: true, college: true, branch: true, year: true }
    })
    res.json(user)
  } catch (error) {
    res.status(500).json({ message: 'Failed to update profile' })
  }
})
// ==================== LEADERBOARD & POINTS ROUTES ====================

// Points configuration
const POINTS_CONFIG = {
  EVENT_REGISTRATION: 10,
  EVENT_CHECKIN: 20,
  PHOTO_SHARED: 5,
  COMMENT_POSTED: 3,
  FEEDBACK_GIVEN: 15,
  TESTIMONIAL_APPROVED: 25
}

// Calculate points for a user
async function calculateUserPoints(userId) {
  const [registrations, checkins, photos, comments, feedbacks, testimonials] = await Promise.all([
    prisma.eventRegistration.count({ where: { userId } }),
    prisma.eventCheckin.count({ where: { userId } }),
    prisma.eventPhoto.count({ where: { userId } }),
    prisma.eventComment.count({ where: { userId } }),
    prisma.eventFeedback.count({ where: { userId } }),
    prisma.testimonial.count({ where: { userId, isApproved: true } })
  ])

  return (
    registrations * POINTS_CONFIG.EVENT_REGISTRATION +
    checkins * POINTS_CONFIG.EVENT_CHECKIN +
    photos * POINTS_CONFIG.PHOTO_SHARED +
    comments * POINTS_CONFIG.COMMENT_POSTED +
    feedbacks * POINTS_CONFIG.FEEDBACK_GIVEN +
    testimonials * POINTS_CONFIG.TESTIMONIAL_APPROVED
  )
}

// Get leaderboard
app.get('/leaderboard', async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query

    const users = await prisma.user.findMany({
      where: { isBanned: false },
      select: {
        id: true,
        username: true,
        displayName: true,
        avatarUrl: true,
        points: true,
        college: true,
        createdAt: true,
        _count: {
          select: {
            eventRegistrations: true,
            eventCheckins: true,
            eventPhotos: true,
            eventComments: true
          }
        }
      },
      orderBy: { points: 'desc' },
      take: parseInt(limit),
      skip: parseInt(offset)
    })

    // Add rank to each user
    const rankedUsers = users.map((user, index) => ({
      rank: parseInt(offset) + index + 1,
      ...user,
      stats: {
        eventsAttended: user._count.eventRegistrations,
        checkIns: user._count.eventCheckins,
        photos: user._count.eventPhotos,
        comments: user._count.eventComments
      }
    }))

    // Remove _count from response
    rankedUsers.forEach(u => delete u._count)

    const totalUsers = await prisma.user.count({ where: { isBanned: false } })

    res.json({
      leaderboard: rankedUsers,
      total: totalUsers,
      limit: parseInt(limit),
      offset: parseInt(offset)
    })
  } catch (error) {
    console.error('Leaderboard error:', error)
    res.status(500).json({ message: 'Failed to fetch leaderboard' })
  }
})

// Get top users for widget
app.get('/leaderboard/top', async (req, res) => {
  try {
    const { limit = 5 } = req.query

    const users = await prisma.user.findMany({
      where: { isBanned: false, points: { gt: 0 } },
      select: {
        id: true,
        username: true,
        displayName: true,
        avatarUrl: true,
        points: true
      },
      orderBy: { points: 'desc' },
      take: parseInt(limit)
    })

    const topUsers = users.map((user, index) => ({
      rank: index + 1,
      ...user
    }))

    res.json(topUsers)
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch top users' })
  }
})

// Recalculate all user points (admin only)
app.post('/admin/recalculate-points', verifyToken, requireAdmin, async (req, res) => {
  try {
    const users = await prisma.user.findMany({ select: { id: true } })

    let updated = 0
    for (const user of users) {
      const points = await calculateUserPoints(user.id)
      await prisma.user.update({
        where: { id: user.id },
        data: { points }
      })
      updated++
    }

    res.json({ message: `Recalculated points for ${updated} users` })
  } catch (error) {
    console.error('Points recalculation error:', error)
    res.status(500).json({ message: 'Failed to recalculate points' })
  }
})

// Update user points after activity (internal helper)
async function updateUserPoints(userId) {
  const points = await calculateUserPoints(userId)
  await prisma.user.update({
    where: { id: userId },
    data: { points }
  })
  return points
}

// ==================== NOTIFICATION ROUTES ====================

// Get user notifications
app.get('/notifications', verifyToken, async (req, res) => {
  try {
    const { limit = 20, unreadOnly = false } = req.query

    const where = { userId: req.user.userId }
    if (unreadOnly === 'true') {
      where.isRead = false
    }

    const [notifications, unreadCount] = await Promise.all([
      prisma.notification.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: parseInt(limit)
      }),
      prisma.notification.count({
        where: { userId: req.user.userId, isRead: false }
      })
    ])

    res.json({ notifications, unreadCount })
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch notifications' })
  }
})

// Mark notification as read
app.put('/notifications/:id/read', verifyToken, async (req, res) => {
  try {
    const notification = await prisma.notification.update({
      where: { id: req.params.id, userId: req.user.userId },
      data: { isRead: true }
    })
    res.json(notification)
  } catch (error) {
    res.status(500).json({ message: 'Failed to mark notification as read' })
  }
})

// Mark all notifications as read
app.put('/notifications/mark-all-read', verifyToken, async (req, res) => {
  try {
    await prisma.notification.updateMany({
      where: { userId: req.user.userId, isRead: false },
      data: { isRead: true }
    })
    res.json({ message: 'All notifications marked as read' })
  } catch (error) {
    res.status(500).json({ message: 'Failed to mark notifications as read' })
  }
})

// Create notification (internal helper)
async function createNotification(userId, type, title, message, link = null) {
  return prisma.notification.create({
    data: { userId, type, title, message, link }
  })
}

// ==================== ADMIN ANALYTICS ROUTES ====================

app.get('/admin/analytics', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { days = 30 } = req.query
    const startDate = new Date()
    startDate.setDate(startDate.getDate() - parseInt(days))

    // User growth over time
    const users = await prisma.user.findMany({
      where: { createdAt: { gte: startDate } },
      select: { createdAt: true },
      orderBy: { createdAt: 'asc' }
    })

    // Group users by date
    const userGrowth = {}
    users.forEach(u => {
      const date = u.createdAt.toISOString().split('T')[0]
      userGrowth[date] = (userGrowth[date] || 0) + 1
    })

    const userGrowthArray = Object.entries(userGrowth).map(([date, count]) => ({ date, count }))

    // Event statistics
    const events = await prisma.gfgEvent.findMany({
      where: { startDate: { gte: startDate } },
      include: {
        _count: { select: { registrations: true, checkins: true, feedbacks: true } }
      },
      orderBy: { startDate: 'desc' }
    })

    const eventStats = events.map(e => ({
      id: e.id,
      title: e.title,
      date: e.startDate,
      registrations: e._count.registrations,
      attendance: e._count.checkins,
      feedbacks: e._count.feedbacks
    }))

    // Overall engagement metrics
    const [totalUsers, activeUsers, totalEvents, totalCheckins, totalPoints] = await Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { points: { gt: 0 } } }),
      prisma.gfgEvent.count(),
      prisma.eventCheckin.count(),
      prisma.user.aggregate({ _sum: { points: true } })
    ])

    // Top performers
    const topPerformers = await prisma.user.findMany({
      where: { points: { gt: 0 } },
      select: {
        id: true,
        username: true,
        displayName: true,
        avatarUrl: true,
        points: true,
        _count: { select: { eventCheckins: true } }
      },
      orderBy: { points: 'desc' },
      take: 10
    })

    res.json({
      userGrowth: userGrowthArray,
      eventStats,
      engagement: {
        totalUsers,
        activeUsers,
        totalEvents,
        totalCheckins,
        totalPoints: totalPoints._sum.points || 0,
        avgPointsPerUser: totalUsers > 0 ? Math.round((totalPoints._sum.points || 0) / totalUsers) : 0
      },
      topPerformers: topPerformers.map(u => ({
        ...u,
        eventsAttended: u._count.eventCheckins
      }))
    })
  } catch (error) {
    console.error('Analytics error:', error)
    res.status(500).json({ message: 'Failed to fetch analytics' })
  }
})

// Start server (only in non-Vercel environment)
if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => {
    console.log(`✅ GFG Backend running at http://localhost:${PORT}`)
    console.log(`🗄️  Connected to Supabase PostgreSQL`)
    console.log(`📚 Auth: /auth/register, /auth/login, /auth/me`)
    console.log(`📅 Events: /events (GET, POST, PUT, DELETE)`)
    console.log(`📝 Event Registration: /events/:id/register, /registrations`)
  })
}

// Graceful shutdown
process.on('beforeExit', async () => {
  await prisma.$disconnect()
})

// Export for Vercel serverless
export default app
