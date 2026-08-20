FROM node:18-alpine

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
# We install all dependencies (including devDependencies like ts-node)
RUN npm install

# Copy all source files
COPY . .

# Ensure uploads directory exists and has correct permissions
RUN mkdir -p uploads && chmod 777 uploads

# Expose port
EXPOSE 3000

# Start the server using ts-node
CMD ["npm", "start"]
